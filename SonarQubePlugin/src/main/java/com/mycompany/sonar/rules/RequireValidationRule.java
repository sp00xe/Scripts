package com.mycompany.sonar.rules;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.*;

import java.util.List;

@Rule(key = "RequireValidion")
public class RequireValidionRule extends IssuableSubscriptionVisitor {

  private static final String SPRING_REQUEST_BODY = "org.springframework.web.bind.annotation.RequestBody";
  private static final String JAVAX_VALID = "javax.validation.Valid";
  private static final String JAKARTA_VALID = "jakarta.validation.Valid";
  private static final String SPRING_VALIDATED = "org.springframework.validation.annotation.Validated";

  @Override
  public List<Tree.Kind> nodesToVisit() {
    return List.of(Tree.Kind.METHOD);
  }

  @Override
  public void visitNode(Tree tree) {
    MethodTree method = (MethodTree) tree;

    for (VariableTree param : method.parameters()) {
      if (hasAnnotation(param.modifiers(), SPRING_REQUEST_BODY)) {
        boolean hasValid =
          hasAnnotation(param.modifiers(), JAVAX_VALID) ||
          hasAnnotation(param.modifiers(), JAKARTA_VALID) ||
          hasAnnotation(param.modifiers(), SPRING_VALIDATED);

        if (!hasValid) {
          reportIssue(param.simpleName(),
            "Add @Valid/@Validated to validate this @RequestBody at the boundary.");
        }
      }
    }
  }

  private static boolean hasAnnotation(ModifiersTree modifiers, String fqn) {
    return modifiers.annotations().stream()
      .map(a -> a.annotationType().symbolType().fullyQualifiedName())
      .anyMatch(fqn::equals);
  }
}