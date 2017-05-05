package pt.ulisboa.tecnico.meic.sec;

import java.io.IOException;
import java.util.ArrayList;

public class ServerCallsPool {
    private final String thisPort = System.getenv("SERVER_PORT");
    private int initialPort = 3001;
    private int finalPort = 3004;

    private ArrayList<SingleServerCalls> singleServerCalls;

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
        return singleServerCalls.size();
    }

    private void init() {
        singleServerCalls = new ArrayList<>();
        for (int i = initialPort; i <= finalPort; i++) {
            System.out.println("PORT: " + i + " vs " + thisPort);
            if (i == Integer.valueOf(thisPort)) {
                System.out.println("Skipping " + i);
            } else {
                singleServerCalls.add(new SingleServerCalls(i));
            }
        }
    }

    public User[] register(User user) throws IOException {
        Thread[] threads = new Thread[size()];
        User[] usersResponses = new User[size()];

        for (int i = 0; i < size() || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    usersResponses[finalI] = singleServerCalls.get(finalI).register(user);
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
        Thread[] threads = new Thread[size()];
        Password[] passwordsResponse = new Password[size()];
        for (int i = 0; i < size() || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls.get(finalI).putPassword(pwd);
                } catch (Exception e) {
                    // e.printStackTrace(System.out);
                    System.out.println(e.getMessage());
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
                e.printStackTrace(System.out);
            }
        }
        return passwordsResponse;
    }


    public Password[] retrievePassword(Password pwd) throws IOException {
        Thread[] threads = new Thread[size()];
        Password[] passwordsResponse = new Password[size()];
        for (int i = 0; i < size() || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls.get(finalI).retrievePassword(pwd);
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


    public Password[] lock(Password pwd)  {
        Thread[] threads = new Thread[size()];
        Password[] passwordsResponse = new Password[size()];
        for (int i = 0; i < size() || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls.get(finalI).lock(pwd);
                } catch (Exception e) {
                    // e.printStackTrace(System.out);
                    System.out.println(e.getMessage());
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
                e.printStackTrace(System.out);
            }
        }
        return passwordsResponse;
    }

    //Mockup purpose
    @Deprecated
    public void setSingleServerCalls(SingleServerCalls[] singleServerCalls) {
        //this.singleServerCalls = singleServerCalls;
    }

    public void setSingleServerCalls(ArrayList<SingleServerCalls> singleServerCalls) {
        this.singleServerCalls = singleServerCalls;
    }
}
