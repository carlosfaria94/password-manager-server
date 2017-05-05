package pt.ulisboa.tecnico.meic.sec;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

public class Transaction {
    private ArrayList<Password> passwords;
    private long timestamp;
    private ReentrantLock lock;
    private ReentrantLock markFirstCommit;
    private AtomicBoolean isCommited;

    public Transaction(){
        passwords = new ArrayList<>();
        timestamp = System.currentTimeMillis();
        lock = new ReentrantLock();
        markFirstCommit = new ReentrantLock();
        isCommited = new AtomicBoolean(false);
    }

    public Transaction(boolean lock){
        this();
        if(lock) lock();
    }

    public synchronized boolean isCommited(){
        return isCommited.get();
    }

    public synchronized void setCommited(){
        isCommited.set(true);
    }

    public synchronized boolean markFirstCommit(){
        return markFirstCommit.tryLock();
    }

    public synchronized Password[] getPasswords() {
        return passwords.toArray(new Password[passwords.size()]);
    }

    public synchronized boolean hasExpired(){
        return System.currentTimeMillis() - timestamp > 1000*60;
    }

    public synchronized boolean hasServerResponded(String serverPublicKey){
        for(Password p: passwords){
            if(p.serverPublicKey.equals(serverPublicKey))
                return true;
        }
        return false;
    }

    public synchronized boolean isLocked(){
        return lock.isLocked();
    }

    public synchronized boolean tryLock(){
        return lock.tryLock();
    }

    public synchronized void lock(){
        lock.lock();
    }

    public synchronized void unlock(){
        lock.unlock();
    }

    public synchronized void addPassword(Password password){
        passwords.add(password);
    }
}
