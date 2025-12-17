package com.mycompany.sonar;

import org.sonar.api.server.rule.RulesDefinition;

public class MyRulesDefinition implements RulesDefinition {
  public static final String REPOSITORY_KEY = "mycompany-java";
  public static final String LANGUAGE_KEY = "java";

  @Override
  public void define(Context context) {
    NewRepository repo = context
      .createRepository(REPOSITORY_KEY, LANGUAGE_KEY)
      .setName("MyCompany Java Rules");

    // Register one rule
    repo.createRule("AvoidFoo")
      .setName("Avoid calling foo()")
      .setHtmlDescription(loadHtml("AvoidFooRule.html"))
      .setSeverity("MAJOR")
      .setTags("bug", "security");

    repo.done();
  }

  private static String loadHtml(String resourceName) {
    try (var in = MyRulesDefinition.class.getResourceAsStream("/com/mycompany/sonar/rules/" + resourceName)) {
      if (in == null) return "<p>Missing rule description</p>";
      return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    } catch (Exception e) {
      return "<p>Error loading rule description</p>";
    }
  }
}
