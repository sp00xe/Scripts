package com.mycompany.sonar;

import org.sonar.api.Plugin;

public class MyCompanyPlugin implements Plugin {
  @Override
  public void define(Context context) {
    context.addExtensions(
      MyRulesDefinition.class,
      MyJavaRulesRegistrar.class
    );
  }
}
