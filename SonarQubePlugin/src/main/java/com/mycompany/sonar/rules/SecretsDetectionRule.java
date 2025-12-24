package com.mycompany.sonar.rules;

import org.sonar.check.Rule;
import org.sonar.check.RuleProperty;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.LiteralTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

import java.util.List;
import java.util.regex.Pattern;

@Rule(key = "HardcodedSecret")
public class HardcodedSecretRule extends IssuableSubscriptionVisitor {

  @RuleProperty(
    key = "secretPatterns",
    description = "Newline-separated regular expressions used to detect secrets in string literals.",
    defaultValue =
      // AWS Access Key ID (AKIA/ASIA...)
      "(?i)\\b(AKIA|ASIA)[0-9A-Z]{16}\\b\n" +
      // AWS Secret Access Key (40 chars base64-ish) - heuristic
      "(?i)\\baws(.{0,20})?secret(.{0,20})?key\\b.*[A-Za-z0-9/+=]{40}\n" +
      // GitHub token (classic + fine-grained) - heuristic
      "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b\n" +
      // Slack token - heuristic
      "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b\n" +
      // Private key header
      "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----\n" +
      // Generic “password=…”, “apiKey: …” etc. (keep strict-ish)
      "(?i)\\b(password|passwd|pwd|secret|api[_-]?key|token|auth|bearer)\\b\\s*[:=]\\s*['\\\"]?[A-Za-z0-9_\\-/.+=]{8,}['\\\"]?"
  )
  public String secretPatterns = "";

  @RuleProperty(
    key = "allowlistPatterns",
    description = "Newline-separated regexes. If a string matches any allowlist pattern, it will not be reported.",
    defaultValue =
      // Common placeholders
      "(?i)\\b(change(me)?|replace(me)?|your[_-]?token|your[_-]?key|dummy|example|test)\\b\n" +
      // Localhost URLs etc.
      "(?i)\\bhttps?://localhost\\b"
  )
  public String allowlistPatterns = "";

  @RuleProperty(
    key = "secretNamePatterns",
    description = "Newline-separated regexes for variable/field names that suggest secrets.",
    defaultValue =
      "(?i).*api.*\n" +
      "(?i).*key.*\n" +
      "(?i).*secret.*\n" +
      "(?i).*token.*\n" +
      "(?i).*password.*\n" +
      "(?i).*passwd.*\n" +
      "(?i).*pwd.*\n" +
      "(?i).*private[_-]?key.*"
  )
  public String secretNamePatterns = "";

  private volatile List<Pattern> compiledSecrets;
  private volatile List<Pattern> compiledAllowlist;
  private volatile List<Pattern> compiledSecretNames;

  @Override
  public List<Tree.Kind> nodesToVisit() {
    // STRING_LITERAL catches general hardcoded secrets.
    // VARIABLE catches "secret-looking" variable names assigned to literals.
    return List.of(Tree.Kind.STRING_LITERAL, Tree.Kind.VARIABLE);
  }

  @Override
  public void visitNode(Tree tree) {
    ensureCompiled();

    if (tree.is(Tree.Kind.VARIABLE)) {
      handleVariable((VariableTree) tree);
      return;
    }

    if (tree.is(Tree.Kind.STRING_LITERAL)) {
      handleStringLiteral((LiteralTree) tree);
    }
  }

  private void handleVariable(VariableTree var) {
    // Only apply to String variables/fields
    if (var.type() == null
        || var.type().symbolType() == null
        || !"java.lang.String".equals(var.type().symbolType().fullyQualifiedName())) {
      return;
    }

    if (var.initializer() == null || !var.initializer().is(Tree.Kind.STRING_LITERAL)) {
      return;
    }

    String varName = var.simpleName().name();
    LiteralTree lit = (LiteralTree) var.initializer();
    String value = lit.value();

    if (value == null || value.isBlank()) return;

    // Reduce noise: only consider name-based path if the name looks secret-ish
    if (!matchesAny(compiledSecretNames, varName)) return;

    // Allowlist gets first shot
    if (matchesAny(compiledAllowlist, value)) return;

    // Require the value to look like a secret too (keeps false positives down)
    if (matchesAny(compiledSecrets, value)) {
      reportIssue(
        var.simpleName(),
        "Variable '" + varName + "' looks like a secret and is initialized with a hardcoded value. " +
        "Move it to a secrets manager / environment variable and rotate if needed."
      );
    }
  }

  private void handleStringLiteral(LiteralTree lit) {
    String value = lit.value();
    if (value == null || value.isBlank()) return;

    if (matchesAny(compiledAllowlist, value)) return;

    if (matchesAny(compiledSecrets, value)) {
      reportIssue(
        lit,
        "Possible hardcoded secret detected. Move it to a secrets manager / environment variable and rotate if needed."
      );
    }
  }

  private void ensureCompiled() {
    if (compiledSecrets == null || compiledAllowlist == null || compiledSecretNames == null) {
      compiledSecrets = compileNewlineSeparated(secretPatterns);
      compiledAllowlist = compileNewlineSeparated(allowlistPatterns);
      compiledSecretNames = compileNewlineSeparated(secretNamePatterns);
    }
  }

  private static List<Pattern> compileNewlineSeparated(String rules) {
    if (rules == null || rules.isBlank()) return List.of();
    return rules.lines()
      .map(String::trim)
      .filter(s -> !s.isEmpty())
      .map(p -> Pattern.compile(p, Pattern.DOTALL))
      .toList();
  }

  private static boolean matchesAny(List<Pattern> patterns, String s) {
    for (Pattern p : patterns) {
      if (p.matcher(s).find()) return true;
    }
    return false;
  }
}