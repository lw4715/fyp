import java.util.concurrent.Callable;

public class JasperCallable implements Callable {
//    private Thread t;
    private String name;
    private QueryExecutor qe;
    private boolean all;


    JasperCallable() {
        System.out.println("Callable created " + this);
        this.qe = QueryExecutor.getInstance();
    }



    void setName(String name) {
        this.name = name;
    }

    void setAll(boolean all) {
        this.all = all;
    }

    @Override
    public Result call() throws Exception {
        System.out.println("Running... " + name);
        return qe.execute(name, all);
    }
}
