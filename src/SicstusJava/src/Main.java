import se.sics.jasper.*;//import se.sics.jasper.*;

public class Main {
//    static String[] cases = new String[]{"us_bank_hack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"};

    /*
    mode 0 = tech
    mode 1 = op
    mode 2 = str
    */
    static void executeQuery(int mode, String[] argv) {
        String prologFile;

        SICStus sp;
        SPPredicate pred;
        SPTerm attack, culprit, d1, d2, d3, d4, d5, r;
        SPQuery query;

        try
        {
            sp = new SICStus(argv,null);
            SPCanonicalAtom TIMEOUT = new SPCanonicalAtom(sp, "time_out");
            r = new SPTerm(sp, "success");

            switch(mode) {
                case 0:
                    prologFile = "../Prolog_files/tech_rules.pl";
                    sp.load(prologFile);
                    pred = new SPPredicate(sp, "goal", 7, "");
                    attack = new SPTerm(sp).putVariable();
                    culprit = new SPTerm(sp).putVariable();
                    d1 = new SPTerm(sp).putVariable();
                    d2 = new SPTerm(sp).putVariable();
                    d3 = new SPTerm(sp).putVariable();
                    d4 = new SPTerm(sp).putVariable();
                    d5 = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, d1, d2, d3, d4, d5 });
                    break;
                case 1:
                    prologFile = "../Prolog_files/op_rules.pl";
                    sp.load(prologFile);
                    pred = new SPPredicate(sp, "goal", 5, "");
                    attack = new SPTerm(sp).putVariable();
                    culprit = new SPTerm(sp).putVariable();
                    d1 = new SPTerm(sp).putVariable();
                    d2 = new SPTerm(sp).putVariable();
                    d3 = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, d1, d2, d3 });
                    break;
                case 2:
                    prologFile = "../Prolog_files/str_rules.pl";
                    sp.load(prologFile);
                    pred = new SPPredicate(sp, "goal_with_timeout", 4, "");
                    attack = new SPTerm(sp, argv[0]);
//                    attack = new SPTerm(sp).putVariable();
                    culprit = new SPTerm(sp).putVariable();
                    d1 = new SPTerm(sp).putVariable();
                    r = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, d1, r });
                    break;
                default:
                    attack = null;
                    culprit = null;
                    query = null;
                    System.out.println("ERROR");
                    System.exit(-1);
            }

            while (query.nextSolution()) {
                if (!(TIMEOUT.toString()).equals(r.toString())) {
//                    System.out.println(r);
//                    System.out.println(attack.toString());
                    System.out.println(culprit.toString());
                }
            }
            System.out.println("Finished");
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    public static void main(String argv[]) {
        System.out.println("Case name: " + argv[0]);
        executeQuery(0, argv);
        executeQuery(1, argv);
        executeQuery(2, argv);
    }

}
