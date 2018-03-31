import se.sics.jasper.SICStus;
import se.sics.jasper.SPPredicate;
import se.sics.jasper.SPQuery;
import se.sics.jasper.SPTerm;

import static java.lang.System.currentTimeMillis;

//import se.sics.jasper.*;

public class Main {
    static String[] cases = new String[]{"us_bank_hack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"};

    public static void main(String argv[]) {
        String option = argv[0];
        String prologFile;

        SICStus sp;
        SPPredicate pred;
        SPTerm attack, culprit, d1, d2, d3, d4, d5;
        SPQuery query;

        try
        {
            sp = new SICStus(argv,null);

            switch(option) {
                case "tech":
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
                case "op":
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
                case "str":
                    System.out.println("here");
                    prologFile = "../Prolog_files/str_rules.pl";
                    sp.load(prologFile);
                    pred = new SPPredicate(sp, "goal_with_timeout", 3, "");
                    attack = new SPTerm(sp, cases[0]);

//                    attack = new SPTerm(sp).putVariable();
                    culprit = new SPTerm(sp).putVariable();
                    d1 = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, d1 });
                    break;
                default:
                    attack = null;
                    culprit = null;
                    query = null;
                    System.out.println("Wrong argv: input [\"tech\",\"op\", \"str\"]");
                    System.exit(-1);
            }



//            pred = new SPPredicate(sp, "goal", 7, "");
////            attack = new SPTerm(sp, cases[0]);
//            attack = new SPTerm(sp).putVariable();
//            culprit = new SPTerm(sp).putVariable();
//            d1 = new SPTerm(sp).putVariable();
//            d2 = new SPTerm(sp).putVariable();
//            d3 = new SPTerm(sp).putVariable();
//            d4 = new SPTerm(sp).putVariable();
//            d5 = new SPTerm(sp).putVariable();

//            query = sp.openQuery(pred, new SPTerm[] { attack, culprit, d1, d2, d3, d4, d5 });
            float startTime = currentTimeMillis();
            while (currentTimeMillis() - startTime < 5*1000 && query.nextSolution()) {
                System.out.println(attack.toString());
                System.out.println(culprit.toString());
                startTime = currentTimeMillis();
            }
            System.out.println("Finished");
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

}
