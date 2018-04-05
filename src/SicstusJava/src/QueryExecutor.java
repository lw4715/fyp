import se.sics.jasper.*;

import java.util.HashMap;
import java.util.Map;

public class QueryExecutor {
    static String[] cases = new String[]{"us_bank_hack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"};

    Map<String, Integer> techMap;
    Map<String, Integer> opMap;
    Map<String, Integer> strMap;

    QueryExecutor() {
        this.techMap = new HashMap<>();
        this.opMap = new HashMap<>();
        this.strMap = new HashMap<>();
    }

    /*
    (mode)
    0 : tech
    1 : op
    2 : str
    */
    void executeQuery(int mode, String[] argv, boolean verbose) {
        String prologFile;

        SICStus sp;
        SPPredicate pred;
        SPTerm attack, culprit, r;
        SPQuery query;
        Map<String, Integer> acc;
        String label;
        int res;

        try
        {
            sp = new SICStus(argv,null);
            SPCanonicalAtom TIMEOUT = new SPCanonicalAtom(sp, "time_out");
            r = new SPTerm(sp, "success");
            SPTerm[] ds;

            switch(mode) {
                case 0:
                    label = "t";
                    acc = techMap;
                    prologFile = "../Prolog_files/tech_rules.pl";
                    sp.load(prologFile);
                    pred = new SPPredicate(sp, "goal", 7, "");
                    attack = new SPTerm(sp).putVariable();
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[5];
                    ds[0] = new SPTerm(sp).putVariable();
                    ds[1] = new SPTerm(sp).putVariable();
                    ds[2] = new SPTerm(sp).putVariable();
                    ds[3] = new SPTerm(sp).putVariable();
                    ds[4] = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, ds[0], ds[1], ds[2], ds[3], ds[4] });
                    break;
                case 1:
                    label = "op";
                    acc = opMap;
                    prologFile = "../Prolog_files/op_rules.pl";
                    sp.load(prologFile);
                    pred = new SPPredicate(sp, "goal", 5, "");
                    attack = new SPTerm(sp).putVariable();
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[3];
                    ds[0] = new SPTerm(sp).putVariable();
                    ds[1] = new SPTerm(sp).putVariable();
                    ds[2] = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, ds[0], ds[1], ds[2] });
                    break;
                case 2:
                    label = "str";
                    acc = strMap;
                    prologFile = "../Prolog_files/str_rules.pl";
                    sp.load(prologFile);
                    pred = new SPPredicate(sp, "goal_with_timeout", 4, "");
                    attack = new SPTerm(sp, argv[0]);
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

            while (query.nextSolution()) {
                if (!TIMEOUT.toString().equals(r.toString())) {
                    for (int i = 0; i < ds.length; i++) {
                        SPTerm d = ds[i];
                        if (d.toString().charAt(0) != '_') System.out.println(d);
                        if (d.isList()) {
                            // array of rule names corresponding to ith meta evidence
                            SPTerm[] dArray = d.toTermArray();
                            res = 0;
                            for (SPTerm delta : dArray) {
                                res += getScore(delta, mode);
                            }
                            String ruleName = String.format("%s_%s%d", label, attack, i);
//                            System.out.println(ruleName);
                            if (acc.get(ruleName) == null || res > acc.get(ruleName)) {
                                acc.put(ruleName, res);
                            }
                        }
                    }
                    if (verbose) {
                        System.out.println(culprit);
                    }

                }
            }
            System.out.println("Finished");
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    private int getScore(SPTerm delta, int mode) {
        int acc = 0;
        String deltaString = delta.toString();
        String prefix;
        Map<String, Integer> map;
//        System.out.println("m: " + mode);
//        System.out.println("dString: " + deltaString);
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
            if (deltaString.contains(prefix)) {
                if (map.containsKey(deltaString)) {
//                    System.out.println("Retuning " + map.get(deltaString));
                    acc = map.get(deltaString);
                }
            }
        }

        if (deltaString.contains("case")) {
            acc += 2;
        } else if (deltaString.contains("bg")) {
            acc += 1;
        }

        return acc;
    }

    public static void main(String argv[]) {
        boolean verbose = false;
        System.out.println("Case name: " + argv[0]);
//        for (String caseName : cases) {
//            argv[0] = caseName;
            QueryExecutor qe = new QueryExecutor();
            qe.executeQuery(0, argv, verbose);
            qe.executeQuery(1, argv, verbose);
            qe.executeQuery(2, argv, verbose);
            System.out.println("--------- \nBreakdown");
            System.out.println(qe.techMap);
            System.out.println(qe.opMap);
            System.out.println(qe.strMap);
        }
//    }

}
