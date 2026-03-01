class Demo {
    void go(String cmd) throws Exception {
        // ruleid: java.runtime-exec
        Runtime.getRuntime().exec(cmd);
    }
}
