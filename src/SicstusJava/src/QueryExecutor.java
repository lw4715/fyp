import se.sics.jasper.*;

import java.util.*;

import static java.lang.Math.pow;

@SuppressWarnings("ALL")
public class QueryExecutor {
    // TODO: update to relative filepath of prolog files
    static String FILEPATH = "";
    Map<String, Integer> techMap;
    Map<String, Integer> opMap;
    Map<String, Integer> strMap;
    Map<String, Integer> culprits;


    QueryExecutor() {
        techMap = new HashMap<>();
        opMap = new HashMap<>();
        strMap = new HashMap<>();
        culprits = new HashMap<>();
    }

    public String culpritString() {
        StringBuilder sb = new StringBuilder();
        for (String c : culprits.keySet()) {
            sb.append(String.format("%s [%d]", c, culprits.get(c)));
        }
        return sb.toString();
    }

    /*
    (mode)
    0 : tech
    1 : op
    2 : str
    */
    void executeQuery(int mode, String caseName, boolean verbose) {
        SICStus sp;
        SPPredicate pred;
        SPTerm attack, culprit, r;
        SPQuery query;
        Map<String, Integer> accMap;
        String label;
        int res;
        int numDeltas;

        try
        {
            sp = new SICStus(new String[] {},null);
            SPCanonicalAtom TIMEOUT = new SPCanonicalAtom(sp, "time_out");
            r = new SPTerm(sp, "success");
            SPTerm[] ds;

            switch(mode) {
                case 0:
                    numDeltas = 5;
                    System.out.println("TECHNICAL");
                    label = "t";
                    accMap = techMap;
                    sp.load(FILEPATH + "tech_rules.pl");
                    pred = new SPPredicate(sp, "goal", numDeltas + 2, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[numDeltas];
                    for (int i = 0; i < numDeltas; i++) {
                        ds[i] = new SPTerm(sp).putVariable();
                    }
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, ds[0], ds[1], ds[2], ds[3], ds[4] });
                    break;
                case 1:
                    numDeltas = 3;
                    System.out.println("OPERATIONAL");
                    label = "op";
                    accMap = opMap;
                    sp.load(FILEPATH + "op_rules.pl");
                    pred = new SPPredicate(sp, "goal", numDeltas + 2, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[numDeltas];
                    for (int i = 0; i < numDeltas; i++) {
                        ds[i] = new SPTerm(sp).putVariable();
                    }
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, ds[0], ds[1], ds[2] });
                    break;
                case 2:
                    System.out.println("STRATEGIC");
                    label = "str";
                    accMap = strMap;
                    sp.load(FILEPATH + "str_rules.pl");
                    pred = new SPPredicate(sp, "goal_with_timeout", 4, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[1];
                    ds[0] = new SPTerm(sp).putVariable();
                    r = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, ds[0], r });
                    break;
                default:
                    System.exit(-1);
                    return;
            }

            int count = 0;

            while (query.nextSolution() && count < 50) {
                if (TIMEOUT.toString().equals(r.toString())) {
                    System.out.println("TIMEOUT");
                    continue;
                }
                count++;
                for (int i = 0; i < ds.length; i++) {
                    SPTerm d = ds[i];
                    if (verbose) System.out.println(d);

                    if (d.isList()) {
                        // array of rule names corresponding to ith meta evidence
                        SPTerm[] dArray = d.toTermArray();
                        res = 0;
                        for (SPTerm delta : dArray) {
                            res += getScore(delta, mode);
                        }
                        String ruleName = String.format("%s_%s%d", label, attack, i+1);
                        if (accMap.get(ruleName) == null || res > accMap.get(ruleName)) {
                            accMap.put(ruleName, res);
                        }
                        if (mode == 2) {
                            culprits.put(culprit.toString(), res);
                            System.out.println(culprits);
                        }
                    }
                }
//                if (mode == 2) culprits.put(culprit.toString(), res);
            }

            System.out.println("Finished");
            return;
        } catch ( Exception e ) {
            e.printStackTrace();
            return;
        }
    }

    private int getScore(SPTerm delta, int mode) {
        int acc = 0;
        String deltaString = delta.toString();
        String prefix;
        Map<String, Integer> map;
        if (mode != 0) {
            switch(mode) {
                case 1:
                    prefix = "t_";
                    map = techMap;
                    break;
                case 2:
                    prefix = "op_";
                    map = opMap;
                    break;
                default:
                    return 0;
            }
            if (deltaString.contains(prefix) && map.containsKey(deltaString)) {
                acc = map.get(deltaString);
            }
        }
        if (deltaString.contains("case")) {
            acc += 2;
        } else if (deltaString.contains("bg")) {
            acc += 1;
        }
        return acc;
    }

    public static String execute(String caseName) {
        boolean verbose = true;
        QueryExecutor qe = new QueryExecutor();
        double time = System.nanoTime();
        System.out.println("Start time: " + time);
        qe.executeQuery(0, caseName, verbose);
        double techTime = (System.nanoTime() - time)/pow(10,9);
        time = System.nanoTime();
        System.out.println("Time taken for tech layer: " + techTime + "s");
        qe.executeQuery(1, caseName, verbose);
        double opTime = (System.nanoTime() - time)/pow(10,9);
        time = System.nanoTime();
        System.out.println("Time taken for op layer: " + opTime + "s");
        time = System.currentTimeMillis();
        qe.executeQuery(2, caseName, verbose);
        double strTime = (System.nanoTime() - time)/pow(10,9);
        System.out.println("Time taken for str layer: " + strTime + "s");
        System.out.println("Total time: " + (techTime + opTime + strTime));
        return String.format("Culprit(s): %s\nTech: %s\nOp: %s\nStr: %s\n",
                qe.culpritString(), qe.techMap, qe.opMap, qe.strMap);
    }

    public static void main(String[] args) {
        //{"us_bank_hack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"};
        System.out.println(execute("gaussattack"));
        System.out.println(execute("gaussattack"));

    }

}
