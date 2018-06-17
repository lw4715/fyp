//import javafx.util.Pair;

import com.sun.tools.javac.util.Pair;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.Map;

public class QueryExecutorWorkers {

    static final Cursor WAIT_CURSOR = Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR);

    static Result execute(String attackName, boolean reload, JFrame f) {
        try {
            f.setCursor(WAIT_CURSOR);
            return new QueryExecutorWorkers.NormalExecutorWorker(attackName, reload, f).doInBackground();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static String customExecute(String customQuery, JFrame f) {
        try {
            f.setCursor(WAIT_CURSOR);
            return new QueryExecutorWorkers.CustomExecutorWorker(customQuery, f).doInBackground();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Map<String, Map<String, Map<String, Integer>>> parseSnortLogs(File file, JFrame f) {
        try {
            f.setCursor(WAIT_CURSOR);
            return new QueryExecutorWorkers.SnortLogWorker(file, f).doInBackground();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Pair<List<String>, List<String>> tryToProve(String strRule, String attackName, JFrame f) {
        try {
            f.setCursor(WAIT_CURSOR);
            return new QueryExecutorWorkers.TryToProveWorker(strRule, attackName, f).doInBackground();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Pair<List<String>, List<String>> tryToProve(String rule, String attackName, String headWithConst, JFrame f) {
        try {
            f.setCursor(WAIT_CURSOR);
            return new QueryExecutorWorkers.TryToProveWorker(rule, attackName, headWithConst, f).doInBackground();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Map<String, List<String>> getPredMap(List<String> preds, boolean isAss, JFrame f) {
        try {
            f.setCursor(WAIT_CURSOR);
            return new QueryExecutorWorkers.PredMapWorker(preds, isAss, f).doInBackground();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static class NormalExecutorWorker extends SwingWorker<Result, Void> {
        String attackName;
        private final boolean reload;
        QueryExecutor qe;
        private final JFrame f;

        NormalExecutorWorker(String attackName, boolean reload, JFrame f) {
            this.attackName = attackName;
            this.reload = reload;
            this.f = f;
            qe = QueryExecutor.getInstance();
        }

        @Override
        protected Result doInBackground() throws Exception {
            Result ret = this.qe.execute(this.attackName, this.reload);
            this.f.setCursor(Cursor.getDefaultCursor());
            return ret;
        }
    }

    private static class CustomExecutorWorker extends SwingWorker<String, Void> {
        QueryExecutor qe;
        private final String customQuery;
        private final JFrame f;

        CustomExecutorWorker(String customQuery, JFrame f) {
            this.customQuery = customQuery;
            this.f = f;
            qe = QueryExecutor.getInstance();
        }

        @Override
        protected String doInBackground() throws Exception {
            String ret = this.qe.executeCustomQuery(this.customQuery);
            this.f.setCursor(Cursor.getDefaultCursor());
            return ret;
        }
    }

    private static class SnortLogWorker extends SwingWorker<Map<String, Map<String, Map<String, Integer>>>, Void> {
        private final File file;
        private final JFrame f;

        public SnortLogWorker(File file, JFrame f) {
            this.file = file;
            this.f = f;
        }

        @Override
        protected Map<String, Map<String, Map<String, Integer>>> doInBackground() throws Exception {
            Map<String, Map<String, Map<String, Integer>>> ret = ToolIntegration.parseSnortLogs(this.file);
            this.f.setCursor(Cursor.getDefaultCursor());
            return ret;
        }
    }

    private static class TryToProveWorker extends SwingWorker<Pair<List<String>, List<String>>, Void> {
        private final String rule;
        private final String attackName;
        private final String headWithConst;
        private final JFrame f;
        private final QueryExecutor qe;

        public TryToProveWorker(String strRule, String attackName, JFrame f) {
            rule = strRule;
            this.attackName = attackName;
            headWithConst = null;
            this.f = f;
            qe = QueryExecutor.getInstance();
        }

        public TryToProveWorker(String rule, String attackName, String headWithConst, JFrame f) {
            this.rule = rule;
            this.attackName = attackName;
            this.headWithConst = headWithConst;
            this.f = f;
            qe = QueryExecutor.getInstance();
        }

        @Override
        protected Pair<List<String>, List<String>> doInBackground() throws Exception {
            Pair<List<String>, List<String>> ret;
            if (this.headWithConst == null) {
                ret = qe.tryToProve(this.rule, this.attackName);
            } else {
                ret = qe.tryToProve(this.rule, this.attackName, this.headWithConst);
            }
            this.f.setCursor(Cursor.getDefaultCursor());
            return ret;
        }
    }

    private static class PredMapWorker extends SwingWorker<Map<String, List<String>>, Void> {
        private final List<String> preds;
        private final boolean isAss;
        private final JFrame f;
        private final QueryExecutor qe;

        public PredMapWorker(List<String> preds, boolean isAss, JFrame f) {
            this.preds = preds;
            this.isAss = isAss;
            this.f = f;
            qe = QueryExecutor.getInstance();
        }

        @Override
        protected Map<String, List<String>> doInBackground() throws Exception {
            Map<String, List<String>> ret = QueryExecutor.getPredMap(this.preds, this.isAss);
            this.f.setCursor(Cursor.getDefaultCursor());
            return ret;
        }
    }
}
