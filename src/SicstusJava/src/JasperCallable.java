import java.util.concurrent.Callable;

public class JasperCallable implements Callable {
//    private Thread t;
    private String name;
    private QueryExecutor qe;


    JasperCallable() {
        System.out.println("Callable created " + this);
        this.qe = new QueryExecutor();
    }

    void setName(String name) {
        this.name = name;
    }

    @Override
    public Result call() throws Exception {
        System.out.println("Running... " + name);
        return qe.execute(name);
    }
}
