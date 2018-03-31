import se.sics.jasper.SICStus;
import se.sics.jasper.SPPredicate;
import se.sics.jasper.SPQuery;
import se.sics.jasper.SPTerm;

//import se.sics.jasper.*;

public class Main {

    public static void main(String argv[]) {

        SICStus sp;
        SPPredicate pred;
        SPTerm from, to, way;
        SPQuery query;
        int i;

        try
        {
            sp = new SICStus(argv,null);

            sp.load("train.pl");

            pred = new SPPredicate(sp, "connected", 4, "");
            to = new SPTerm(sp, "Orebro");
            from = new SPTerm(sp, "Stockholm");
            way = new SPTerm(sp).putVariable();

            query = sp.openQuery(pred, new SPTerm[] { from, to, way, way });

            while (query.nextSolution())
            {
                System.out.println(way.toString());
            }
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

}
