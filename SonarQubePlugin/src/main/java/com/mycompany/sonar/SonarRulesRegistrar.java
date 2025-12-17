package com.mycompany.sonar;

import java.util.List;
import org.sonar.plugins.java.api.CheckRegistrar;
import org.sonar.plugins.java.api.JavaCheck;

import com.mycompany.sonar.rules.AvoidFooRule;

public class MyJavaRulesRegistrar implements CheckRegistrar {

  @Override
  public void register(RegistrarContext context) {
    context.registerClassesForRepository(
      MyRulesDefinition.REPOSITORY_KEY,
      List.of(AvoidFooRule.class),
      List.of() // test checks (optional)
    );
  }
}
