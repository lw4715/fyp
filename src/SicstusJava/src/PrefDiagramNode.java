import guru.nidi.graphviz.attribute.*;
import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;
import guru.nidi.graphviz.model.Graph;
import guru.nidi.graphviz.model.Node;

import java.io.*;
import java.util.*;

import static guru.nidi.graphviz.model.Factory.graph;
import static guru.nidi.graphviz.model.Factory.node;
import static guru.nidi.graphviz.model.Link.to;

public class PrefDiagramNode {
    private final String rule;
    private final Set<PrefDiagramNode> weakerRules;
    private final Color colour;

    PrefDiagramNode(String rule) {
        this.rule = rule;
        this.weakerRules = new HashSet<>();
        if (rule.startsWith("r_t_")) {
            this.colour = Color.SKYBLUE1;
        } else if (rule.startsWith("r_op_")) {
            this.colour = Color.LIGHTYELLOW;
        } else if (rule.startsWith("r_str_")) {
            this.colour = Color.SALMON;
        } else {
            this.colour = Color.GRAY;
        }
    }

    boolean recursiveContain(PrefDiagramNode n, Set<PrefDiagramNode> seen) {
        // cyclic, haven't returned true so far means will not contain n
        if (seen.contains(this)) {
            return false;
        }

        // base case
        if (equals(n)) {
            return true;
        }

        seen.add(this);
        for (PrefDiagramNode weakerRule : this.weakerRules) {
            if (weakerRule.recursiveContain(n, seen)) {
                return true;
            }
        }
        return false;
    }

    void addWeakerRule(PrefDiagramNode node) {
        this.weakerRules.add(node);
    }

    Node createNode() {
        Node node;
        node = node(this.rule).with(this.colour, Style.FILLED, Shape.RECTANGLE);

        for (PrefDiagramNode weakerRule : this.weakerRules) {
            if (weakerRule.recursiveContain(this, new HashSet<>())) {
                node = node.link(to(node(weakerRule.rule)).with(Color.RED, Label.of("Recursive preference!"))).with(Color.RED, Style.BOLD);
            } else {
                node = node.link(to(weakerRule.createNode()));
            }
        }
        return node;
    }

    @Override
    public String toString() {
        return this.rule + " [" + this.weakerRules.size() + "]";
    }

//    @Override
//    public int hashCode() {
//        return rule.hashCode();
//    }
//
//    @Override
//    public boolean equals(Object o) {
//        if (o instanceof PrefDiagramNode) {
//            return this.rule.equals(((PrefDiagramNode) o).rule);
//        }
//        return false;
//    }

    public static void createPreferenceDiagram() {
        Map<String, PrefDiagramNode> map = new HashMap<>();
        try {
            List<String> fs = new ArrayList<>();
            fs.add("all_prefs.pl");
            fs.add(Utils.USER_EVIDENCE_FILENAME);

            for (String f : fs) {
                BufferedReader br = new BufferedReader(new FileReader(f));
                br.lines().forEach(line -> {
                    if (line.split("%")[0].length() > 0 && line.contains("prefer(")) {
                        String head = Utils.getHeadOfLine(line);
                        String p0 = head.substring(head.indexOf("(") + 1, head.indexOf(")") + 1).trim();
                        String p1 = head.substring(head.indexOf(")") + 2, head.lastIndexOf(")")).trim();
                        if (!map.containsKey(p0)) {
                            map.put(p0, new PrefDiagramNode(p0));
                        }
                        PrefDiagramNode p0Node = map.get(p0);
                        if (!map.containsKey(p1)) {
                            map.put(p1, new PrefDiagramNode(p1));
                        }
                        PrefDiagramNode p1Node = map.get(p1);
                        p0Node.addWeakerRule(p1Node);
                    }

                });
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        String f = "pref_diagram.svg";
        String filename = "img/" + f;
        Graph g = graph(filename).directed();

        for (PrefDiagramNode n : map.values()) {
            g = g.with(n.createNode());
        }

        try {
            Graphviz.fromGraph(g.graphAttr().with(RankDir.LEFT_TO_RIGHT))
                    .render(Format.SVG).toFile(new File(filename));
            DerivationNode.svgPostpreocess(filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
