import guru.nidi.graphviz.attribute.Color;
import guru.nidi.graphviz.attribute.Label;
import guru.nidi.graphviz.attribute.Shape;
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
    private Set<DerivationNode> children;
    private int type;
    private List<String> args;

    public DerivationNode(String result, String rulename, List<String> args, int type) {
        this.result = result;
        this.rulename = rulename;
        this.args = args;
        this.children = new HashSet<>();
        this.type = type;
    }

    public DerivationNode(String result, String rulename, List<String> args, int type, Set<DerivationNode> children) {
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

    public String getResult() {
        return this.result;
    }

    static List<DerivationNode> createDiagram(String filename, DerivationNode mainNode, List<DerivationNode> prefs) {
        try {
            Graph g = graph(filename).directed()
                    .with(mainNode.createNode());
            Graphviz.fromGraph(g)
//                    .width(500).render(Format.PNG).toFile(new File(filename));
                .width(100).render(Format.SVG).toFile(new File(filename));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return prefs;
    }

//    private Node createPrefNode() {
//        Node node = node(result).with(Shape.NONE, Style.FILLED);
//        return node;
//    }

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
        Node node = node(result).with(Shape.RECTANGLE, typeColour, Style.FILLED);
        for (DerivationNode child : children) {
            if (result.equals(child.getResult())) {
                node = node.link(to(child.createNode()).with(Label.of(rulename), Color.WHITE));
            } else {
                node = node.link(to(child.createNode()).with(Label.of(rulename)));
            }
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

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (o instanceof DerivationNode) {
            DerivationNode o1 = (DerivationNode) o;
            return this.result.equals(o1.result) && this.rulename.equals(o1.rulename)
                   && this.args.equals(o1.args);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return result.hashCode() * rulename.hashCode() - args.hashCode();
    }

    // TODO: time and then create to make more efficient and time again
    public static List<DerivationNode> createDerivationNode(List<String> names, List<List<String>> args) {
        Deque<DerivationNode> st = new ArrayDeque<>();
        List<DerivationNode> prefs = new ArrayList<>();
        List<Integer> ruleIndices = new ArrayList<>();
        List<Integer> strRuleIndices = new ArrayList<>();

        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i);
            List<String> arg = args.get(i);
            StringJoiner sj = new StringJoiner(",");
            arg.forEach(sj::add);

            String fullname = String.format("%s(%s)", name, sj.toString());
            if (Utils.isRule(name)) {
                if (Utils.isStrRule(name)) {
                    strRuleIndices.add(i);
                } else {
                    ruleIndices.add(i);
                }
            } else if (Utils.isPreference(fullname)) {
                prefs.add(new DerivationNode(Utils.getHead(name, arg), name, arg, -1));
            } else if (Utils.isAss(name)) {
                st.push(new DerivationNode(fullname, "ass", arg, -1));
//            } else if (name.equals("isCulprit")) {
//                st.push(new DerivationNode(name, "", arg, 2));
            } else {
                st.push(new DerivationNode(Utils.getHead(name, arg), name, arg, -1));
            }
        }

        for (int i : ruleIndices) {
            st = processRule(names.get(i), args.get(i), st);
        }

        for (int i : strRuleIndices) {
            st = processRule(names.get(i), args.get(i), st);
        }

        while (st.size() > 1) {
            st.push(combineFinalResult(st.pop(), st.pop()));
        }

        if (st.size() !=  1) {
            System.err.println("ERROR: Not finished popping! " + st.size() + " " + st);
        }

        List<DerivationNode> ret = new ArrayList<>();
        ret.add(st.pop());
        ret.addAll(prefs);
        return ret;
    }

    private static DerivationNode combineFinalResult(DerivationNode d1, DerivationNode d2) {
        if (d1.getResult().equals(d2.getResult())) {
            Set<DerivationNode> l = new HashSet<>();
            l.add(d1);
            l.add(d2);
            return new DerivationNode(d1.getResult(), "", new ArrayList<>(), 2, l);
        }
        return d1;
    }

    // pop relevant evidences off from stack, push itself on and return remaining stack
    private static Deque<DerivationNode> processRule(String name, List<String> args,
                                                     Deque<DerivationNode> st) {
        List<String> bodyList = Utils.getBody(name);
        Set<DerivationNode> body = new HashSet<>();
        String elem;
        List<String> elemArgs;
        Stack<DerivationNode> tmp = new Stack<>();
        while (!st.isEmpty()) {
            DerivationNode n = st.peek();
            elem = n.getRulename();
            elemArgs = n.getArgs();
//            System.out.println("name: " +name + " elem:" + elem + " args: " + elemArgs + " head: " + Utils.getHead(elem, elemArgs).split("\\(")[0] + " body " + bodyList);
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

    static DerivationNode getExampleNode() {
        List<String> l = new ArrayList<>();
        DerivationNode e1 = new DerivationNode("evidence1", "evidence id", l, -1);
        DerivationNode e2 = new DerivationNode("evidence2", "evidence id", l, -1);
        DerivationNode e3 = new DerivationNode("evidence3", "evidence id", l, -1);
        Set<DerivationNode> es = new HashSet<>();
        es.add(e1);
        es.add(e2);
        DerivationNode tech = new DerivationNode("tech result", "technical rulename", l, 0, es);
        Set<DerivationNode> es1 = new HashSet<>();
        es1.add(e3);
        DerivationNode op = new DerivationNode("op result", "operational rulename", l, 1, es1);
        Set<DerivationNode> es2 = new HashSet<>();
        es2.add(tech);
        es2.add(op);
        return new DerivationNode("str result (isCulprit)", "strategic rulename", l, 2, es2);
    }

    static String getDiagramFilename(String attack, int c) {
        return String.format("%s_%d.svg", attack, c);
    }
    // return list of prefs
    public static List<DerivationNode> createDerivationAndSaveDiagram(Term t, String attack, int count) {
        String filename = getDiagramFilename(attack, count);
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
        List<DerivationNode> res = createDerivationNode(names, args);
        DerivationNode mainNode = res.get(0);
        res.remove(0);
        List<DerivationNode> prefs = res;
        System.out.println("node: " + mainNode);
        return createDiagram("img/" + filename, mainNode, prefs);
    }
}

