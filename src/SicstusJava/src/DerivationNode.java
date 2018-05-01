import guru.nidi.graphviz.attribute.Color;
import guru.nidi.graphviz.attribute.Label;
import guru.nidi.graphviz.attribute.Style;
import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;
import guru.nidi.graphviz.model.Graph;
import guru.nidi.graphviz.model.Node;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import static guru.nidi.graphviz.model.Factory.graph;
import static guru.nidi.graphviz.model.Factory.node;
import static guru.nidi.graphviz.model.Link.to;
import static java.lang.Math.pow;

public class DerivationNode {

    private String result;
    private String rulename;
    private List<DerivationNode> children;
    private int type;


    public DerivationNode(String result, String rulename, int type) {
        this.result = result;
        this.rulename = rulename;
        this.children = new ArrayList<>();
        this.type = type;
    }

    public DerivationNode(String result, String rulename, int type, List<DerivationNode> children) {
        this.result = result;
        this.rulename = rulename;
        this.children = children;
        this.type = type;
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
            Graphviz.fromGraph(g).width(500).render(Format.PNG).toFile(new File(filename));
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
    public static DerivationNode createDerivationNode(String[] ds) {
        Stack<DerivationNode> st = new Stack<>();

        for (String d : ds) {
            if (Utils.isRule(d)) {
                st = createDerivationNode(d, st);
            } else if (Utils.isAss(d)) {
                st.push(new DerivationNode(d, "ass", -1));
            } else {
                st.push(new DerivationNode(Utils.getHead(d), d, -1));
            }
        }
        assert st.size() == 1;
        return st.pop();
    }

    // pop relevant evidences off from stack, push itself on and return remaining stack
    private static Stack<DerivationNode> createDerivationNode(String rulename, Stack<DerivationNode> st) {
//        System.out.println("rule:" + rulename);
        List<String> bodyList = Utils.getBody(rulename);
        List<DerivationNode> body = new ArrayList<>();
//        System.out.println("body list:" + bodyList);
//        System.out.println("stack:" + st);
        String elem;
        while (!st.isEmpty()) {
            elem = st.peek().getRulename();
            if (bodyList.contains(Utils.getHead(elem).split("\\(")[0])) {
                body.add(st.pop());
            } else {
//                System.out.println("break");
                break;
            }
        }

        st.push(new DerivationNode(Utils.getHead(rulename), rulename, getType(rulename), body));
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
        DerivationNode e1 = new DerivationNode("evidence1", "evidence id", -1);
        DerivationNode e2 = new DerivationNode("evidence2", "evidence id", -1);
        DerivationNode e3 = new DerivationNode("evidence3", "evidence id", -1);
        List<DerivationNode> es = new ArrayList<>();
        es.add(e1);
        es.add(e2);
        DerivationNode tech = new DerivationNode("tech result", "technical rulename", 0, es);
        List<DerivationNode> es1 = new ArrayList<>();
        es1.add(e3);
        DerivationNode op = new DerivationNode("op result", "operational rulename", 1, es1);
        List<DerivationNode> es2 = new ArrayList<>();
        es2.add(tech);
        es2.add(op);
        return new DerivationNode("str result (isCulprit)", "strategic rulename", 2, es2);
    }

    public static void createDerivationAndSaveDiagram(String[] d, String filename) {
        DerivationNode node = createDerivationNode(d);
        node.createDiagram("img/" + filename);
    }

    public static void main(String[] args) {
        String[] d = new String[] {"ass(notForBlackMarketUse(flame))","case3_f13()",
                "case3_f12()","r_t_bm(gauss)","bg76()","bg79()","case3_f16()","r_t_simCC1(gauss,flame)",
                "r_t_similar(gauss,flame)","case3_f2()","r_str_linkedMalware(equationGrp,gaussattack)"};
        double time = System.nanoTime();
        createDerivationAndSaveDiagram(d, "diag.png");
        time = ((System.nanoTime() - time)/pow(10, 9));
        System.out.println(time);
//        getExampleNode().createDiagram("example.png");
    }
}

