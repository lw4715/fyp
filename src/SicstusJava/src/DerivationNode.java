import guru.nidi.graphviz.attribute.Color;
import guru.nidi.graphviz.attribute.Label;
import guru.nidi.graphviz.attribute.Style;
import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;
import guru.nidi.graphviz.model.Graph;
import guru.nidi.graphviz.model.Node;
import org.jpl7.Term;

import java.io.File;
import java.io.IOException;
import java.util.*;

import static guru.nidi.graphviz.model.Factory.graph;
import static guru.nidi.graphviz.model.Factory.node;
import static guru.nidi.graphviz.model.Link.to;

public class DerivationNode {

    private String result;
    private String rulename;
    private List<DerivationNode> children;
    private int type;
    private List<String> args;


    public DerivationNode(String result, String rulename, List<String> args, int type) {
        this.result = result;
        this.rulename = rulename;
        this.args = args;
        this.children = new ArrayList<>();
        this.type = type;
    }

    public DerivationNode(String result, String rulename, List<String> args, int type, List<DerivationNode> children) {
        this.result = result;
        this.rulename = rulename;
        this.args = args;
        this.children = children;
        this.type = type;
    }

    public List<String> getArgs() {
        return this.args;
    }

    public String getRulename() {
        return this.rulename;
    }

    void addChild(DerivationNode child) {
        children.add(child);
    }

    void createDiagram(String filename) {
        try {
            Graph g = graph(filename).directed()
                    .with(this.createNode());
            Graphviz.fromGraph(g).width(1000).render(Format.PNG).toFile(new File(filename));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    Node createNode() {
        Color typeColour;
        switch (type) {
            case 0: // tech
                typeColour = Color.SKYBLUE1;
                break;
            case 1: // op
                typeColour = Color.LIGHTYELLOW;
                break;
            case 2: // str
                typeColour = Color.SALMON;
                break;
            default: // evidence
                typeColour = Color.LIGHTGRAY;
        }
        Node node = node(result).with(typeColour, Style.FILLED);
        for (DerivationNode child : children) {
            node = node.link(
                    to(child.createNode()).with(Label.of(rulename)));
        }
        return node;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%s (%s)", result, rulename));
        if (!children.isEmpty()) {
            sb.append("{" + children.size() + "}");
            sb.append("\n");
        }
        for (DerivationNode child : children) {
            sb.append(child.toString() + "\t");
        }
        return sb.toString();
    }

    // TODO: time and then create to make more efficient and time again
    public static DerivationNode createDerivationNode(List<String> names, List<List<String>> args) {
        Deque<DerivationNode> st = new ArrayDeque<>();
        List<DerivationNode> prefs = new ArrayList<>();
        List<Integer> ruleIndices = new ArrayList<>();

        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i);
            List<String> arg = args.get(i);
            StringJoiner sj = new StringJoiner(",");
            arg.forEach(sj::add);

            String fullname = String.format("%s(%s)", name, sj.toString());
            if (Utils.isRule(name)) {
                ruleIndices.add(i);
            } else if (Utils.isAss(name)) {
                st.push(new DerivationNode(fullname, "ass", arg, -1));
            } else if (Utils.isPreference(name)) {
                prefs.add(new DerivationNode(Utils.getHead(name, arg), name, arg, -1));
            } else {
                st.push(new DerivationNode(Utils.getHead(name, arg), name, arg, -1));
            }
            System.out.println("stack:" + st);
        }
        for (int i : ruleIndices) {
            st = processRule(names.get(i), args.get(i), st);
        }

        if (st.size() > 1) {
            System.out.println("Not finished popping! " + st.size() + " " + st);
        }
        return st.pop();
    }

    // pop relevant evidences off from stack, push itself on and return remaining stack
    private static Deque<DerivationNode> processRule(String name, List<String> args,
                                                     Deque<DerivationNode> st) {
        List<String> bodyList = Utils.getBody(name);
        List<DerivationNode> body = new ArrayList<>();
        String elem;
        List<String> elemArgs;
        Stack<DerivationNode> tmp = new Stack<>();
        while (!st.isEmpty()) {
            DerivationNode n = st.peek();
            elem = n.getRulename();
            elemArgs = n.getArgs();
            System.out.println("elem:" + elem + " args: " + elemArgs + " head: " + Utils.getHead(elem, elemArgs).split("\\(")[0] + " body " + bodyList);
            if (bodyList.contains(Utils.getHead(elem, elemArgs).split("\\(")[0])) {
                body.add(st.pop());
            } else {
                tmp.push(st.pop());
            }
        }

        while (!tmp.isEmpty()) {
            st.push(tmp.pop());
        }

        st.push(new DerivationNode(Utils.getHead(name, args), name, args, getType(name), body));
        return st;
    }

    private static int getType(String r) {
        if (r.startsWith("r_t_")) {
            return 0;
        } else if (r.startsWith("r_op_")) {
            return 1;
        } else if (r.startsWith("r_str_")) {
            return 2;
        } else {
            return -1;
        }
    }

    private static DerivationNode getExampleNode() {
        List<String> l = new ArrayList<>();
        DerivationNode e1 = new DerivationNode("evidence1", "evidence id", l, -1);
        DerivationNode e2 = new DerivationNode("evidence2", "evidence id", l, -1);
        DerivationNode e3 = new DerivationNode("evidence3", "evidence id", l, -1);
        List<DerivationNode> es = new ArrayList<>();
        es.add(e1);
        es.add(e2);
        DerivationNode tech = new DerivationNode("tech result", "technical rulename", l, 0, es);
        List<DerivationNode> es1 = new ArrayList<>();
        es1.add(e3);
        DerivationNode op = new DerivationNode("op result", "operational rulename", l, 1, es1);
        List<DerivationNode> es2 = new ArrayList<>();
        es2.add(tech);
        es2.add(op);
        return new DerivationNode("str result (isCulprit)", "strategic rulename", l, 2, es2);
    }

    public static void createDerivationAndSaveDiagram(Term t, String filename) {
        List<String> names = new ArrayList<>();
        List<List<String>> args = new ArrayList<>();
        if (t.isListPair()) {
            for (Term term : t.toTermArray()) {
                names.add(term.name());
                List<String> l = new ArrayList<>();
                for (int i = 1; i <= term.arity(); i++) {
                    l.add(term.arg(i).toString());
                }
                args.add(l);
            }
        }
        final StringJoiner sj = new StringJoiner(",");
        names.forEach(x -> sj.add(x));
        System.out.println(filename + ": " + sj);
        DerivationNode node = createDerivationNode(names, args);
        System.out.println("node: " + node);
        node.createDiagram("img/" + filename);
    }
}

