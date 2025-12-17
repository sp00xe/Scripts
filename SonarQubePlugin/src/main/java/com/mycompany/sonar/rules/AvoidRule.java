package com.mycompany.sonar.rules;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;

import java.util.List;

@Rule(key = "AvoidFoo")
public class AvoidFooRule extends IssuableSubscriptionVisitor {

  @Override
  public List<Tree.Kind> nodesToVisit() {
    return List.of(Tree.Kind.METHOD_INVOCATION);
  }

  @Override
  public void visitNode(Tree tree) {
    MethodInvocationTree mit = (MethodInvocationTree) tree;

    // Simple example: match method name "foo"
    String methodName = mit.symbol().name();
    if ("foo".equals(methodName)) {
      reportIssue(mit.methodSelect(), "Avoid calling foo(); use bar() instead.");
    }
  }
}
