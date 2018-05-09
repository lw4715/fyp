import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

public class JasperCallable implements Callable {
//    private Thread t;
    private String name;
    private QueryExecutor qe;
    private boolean all;
    private boolean reload;
    private List<String> culpritsList = new ArrayList<>();


    JasperCallable() {
        this.qe = QueryExecutor.getInstance();
    }

    void setName(String name) {
        this.name = name;
    }

    void setAll(boolean all) {
        this.all = all;
    }

    public void setReload(boolean reload) {
        this.reload = reload;
    }

    public void setCulpritsList(List<String> culpritsList) {
        this.culpritsList = culpritsList;
    }

    @Override
    public Result call() throws Exception {
        if (all) {
            return qe.executeAll(name, culpritsList);
        } else {
            return qe.execute(name, reload, culpritsList);
        }
    }
}
