import java.util.concurrent.Callable;

public class JasperCallable implements Callable {
//    private Thread t;
    private String name;
    private QueryExecutor qe;
    private boolean all;


    JasperCallable() {
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
        return qe.execute(name, all);
    }
}
