package pt.ulisboa.tecnico.meic.sec;

import java.io.IOException;

public class ServerCallsPool {
    private final String thisPort = System.getenv("SERVER_PORT");
    private int initialPort = 3001;
    private int finalPort = 3004;

    private SingleServerCalls[] singleServerCalls;

    public ServerCallsPool(int initialPort, int finalPort) {
        this.initialPort = initialPort;
        this.finalPort = finalPort;
        init();
    }

    public ServerCallsPool(int replicas) {
        this.finalPort = this.initialPort + replicas - 1;
        init();
    }

    public ServerCallsPool() {
        init();
    }

    public int size() {
        return singleServerCalls.length;
    }

    private void init() {
        singleServerCalls = new SingleServerCalls[finalPort - initialPort];
        for (int i = 0; i < singleServerCalls.length; i++) {
            if (initialPort + i == Integer.valueOf(thisPort)) continue;
            singleServerCalls[i] = new SingleServerCalls(initialPort + i);
        }
    }

    public User[] register(User user) throws IOException {
        Thread[] threads = new Thread[singleServerCalls.length];
        User[] usersResponses = new User[singleServerCalls.length];

        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    usersResponses[finalI] = singleServerCalls[finalI].register(user);
                } catch (Exception ignored) {
                    // If a thread crashed, it's probably connection problems
                }
            });
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        return usersResponses;
    }


    public Password[] putPassword(Password pwd) throws IOException {
        Thread[] threads = new Thread[singleServerCalls.length];
        Password[] passwordsResponse = new Password[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls[finalI].putPassword(pwd);
                } catch (Exception e) {
                    e.printStackTrace(System.out);
                    System.out.println(e.getMessage());
                    // If a thread crashed, it's probably connection problems
                }
            });
        }
        System.out.println("Montei as threads");
        for (Thread thread : threads) {
            thread.start();
        }
        System.out.println("Comecei as threads");

        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace(System.out);
            }
        }
        System.out.println("acabou " + passwordsResponse[0]);

        return passwordsResponse;
    }

    public Password[] retrievePassword(Password pwd) throws IOException {
        Thread[] threads = new Thread[singleServerCalls.length];
        Password[] passwordsResponse = new Password[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls[finalI].retrievePassword(pwd);
                } catch (Exception ignored) {
                    // If a thread crashed, it's probably connection problems
                }
            });
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        return passwordsResponse;
    }

    //Mockup purpose
    public void setSingleServerCalls(SingleServerCalls[] singleServerCalls) {
        this.singleServerCalls = singleServerCalls;
    }
}
