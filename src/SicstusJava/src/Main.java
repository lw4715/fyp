import se.sics.jasper.SICStus;
import se.sics.jasper.SPPredicate;
import se.sics.jasper.SPQuery;
import se.sics.jasper.SPTerm;

//import se.sics.jasper.*;

public class Main {
    String[] cases = new String[]{"us_bank_hack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"};

    public static void main(String argv[]) {
        String option = argv[1];
        String prologFile = "";
        switch(option) {
            case "tech":
                prologFile = "../Prolog_files/tech_rules.pl";
                break;
            case "op":
                prologFile = "../Prolog_files/op_rules.pl";
                break;
            case "str":
                prologFile = "../Prolog_files/str_rules.pl";
                break;
            default:
                System.exit(-1);
        }

        SICStus sp;
        SPPredicate pred;
        SPTerm attack, culprit, d1, d2, d3, d4, d5;
        SPQuery query;

        try
        {
            sp = new SICStus(argv,null);

            sp.load(prologFile);

            pred = new SPPredicate(sp, "goal", 7, "");
//            attack = new SPTerm(sp, cases[0]);
            attack = new SPTerm(sp).putVariable();
            culprit = new SPTerm(sp).putVariable();
            d1 = new SPTerm(sp).putVariable();
            d2 = new SPTerm(sp).putVariable();
            d3 = new SPTerm(sp).putVariable();
            d4 = new SPTerm(sp).putVariable();
            d5 = new SPTerm(sp).putVariable();


            query = sp.openQuery(pred, new SPTerm[] { attack, culprit, d1, d2, d3, d4, d5 });

            while (query.nextSolution())
            {
                System.out.println(attack.toString());
            }
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

}
