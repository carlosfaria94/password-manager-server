package pt.ulisboa.tecnico.meic.sec;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

public class Transaction {
    public static final int INIT_STATE = 0;
    public static final int PREPREPARE_STATE = 1;
    public static final int PREPARE_STATE = 2;
    public static final int COMMIT_STATE = 3;

    private ArrayList<Password> prepare;
    private ArrayList<Password> commits;
    private long timestamp;

    private AtomicInteger state;

    public Transaction(){
        state = new AtomicInteger(INIT_STATE);
        prepare = new ArrayList<>();
        commits = new ArrayList<>();
        timestamp = System.currentTimeMillis();
    }

    public synchronized boolean setPrePrepareState() {
        if (state.compareAndSet(INIT_STATE, PREPREPARE_STATE)){
            restartTimer();
            return true;
        }
        return false;
    }

    public synchronized boolean setPrepareState() {
        if (state.compareAndSet(PREPREPARE_STATE, PREPARE_STATE)){
            restartTimer();
            return true;
        }
        return false;
    }

    public synchronized boolean setCommitState() {
        if (state.compareAndSet(PREPARE_STATE, COMMIT_STATE)){
            restartTimer();
            return true;
        }
        return false;
    }

    public synchronized int getState(){
        return state.get();
    }

    public synchronized Password[] getPrepareAns() {
        return prepare.toArray(new Password[prepare.size()]);
    }

    public synchronized Password[] getCommitsAns() {
        return commits.toArray(new Password[commits.size()]);
    }

    public synchronized boolean hasExpired(){
        return System.currentTimeMillis() - timestamp > 1000*60;
    }

    public synchronized boolean addPrepare(Password password){
        if(!hasServerResponse(prepare, password)) {
            prepare.add(password);
            return true;
        }
        return false;
    }
    public synchronized boolean addCommit(Password password){
        if(!hasServerResponse(commits, password)) {
            commits.add(password);
            return true;
        }
        return false;
    }

    public synchronized boolean hasServerResponse(ArrayList<Password> array, Password password){
        for(Password p: array){
            if(p.serverPublicKey.equals(password.serverPublicKey)) return true;
        }
        return false;
    }

    private synchronized void restartTimer(){
        timestamp = System.currentTimeMillis();
    }
}
