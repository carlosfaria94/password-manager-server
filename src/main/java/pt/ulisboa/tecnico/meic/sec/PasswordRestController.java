package pt.ulisboa.tecnico.meic.sec;

import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pt.ulisboa.tecnico.meic.sec.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.exception.ExpiredTimestampException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidPasswordSignatureException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidRequestSignatureException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

@RestController
class PasswordRestController {

    private final PasswordRepository passwordRepository;

    private final UserRepository userRepository;
    private final String keystorePath;
    private final String keystorePwd;
    private final String serverName = System.getenv("SERVER_NAME");
    private ServerCallsPool call;
    private Gson json = new Gson();

    private ConcurrentHashMap<Password, Transaction> transactions;

    private Security sec;

    @Autowired
    PasswordRestController(PasswordRepository passwordRepository,
                           UserRepository userRepository) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
        keystorePath = "keystore-" + serverName + ".jceks";
        keystorePwd = "batata";
        sec = new Security(keystorePath, keystorePwd.toCharArray());
        call = new ServerCallsPool();
        transactions = new ConcurrentHashMap<>();
        new ClearExpiredTransactions();
    }

    @RequestMapping(value = "/retrievePassword", method = RequestMethod.POST)
    ResponseEntity<?> retrievePassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, InvalidPasswordSignatureException, ExpiredTimestampException, DuplicateRequestException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        String fingerprint = this.validateUser(input.publicKey);
        sec.verifyPasswordFetchSignature(input);
        ArrayList<Password> passwords = new ArrayList<>(this.passwordRepository.findTop10ByOrderById());

        if (passwords.isEmpty()) {
            return new ResponseEntity<>(null, null, HttpStatus.NOT_FOUND);
        } else {
            Password maximum = passwords.get(0);
            for (Password p : passwords) {
                if (Long.valueOf(p.timestamp) >
                        Long.valueOf(maximum.timestamp)) {
                    maximum = p;
                }
            }
            Password p = sec.getPasswordReadyToSendToClient(new Password(maximum));
            return new ResponseEntity<>(p, null, HttpStatus.OK);
        }
    }

    @RequestMapping(value = "/password", method = RequestMethod.PUT)
    ResponseEntity<?> addPassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, ExpiredTimestampException, DuplicateRequestException, InvalidPasswordSignatureException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException, IOException {
        String fingerprint = this.validateUser(input.publicKey);
        sec.verifyPasswordInsertSignature(input);

        Transaction transaction = transactions.get(input);
        if(transaction != null && transaction.getState() != Transaction.INIT_STATE){
            //Resource is locked
            return new ResponseEntity<>(null, null, HttpStatus.LOCKED);
        }

        transaction = new Transaction();
        transaction.setPrePrepareState();

        call.prePrepare(sec.getPasswordReadyToSend(new Password(input)));

        transaction.setPrepareState();
        transactions.put(input, transaction);


        //Wait for enough responses or transaction expires
        while(!enoughResponses(transaction.getPrepareAns(), 1) && !transaction.hasExpired());

        //NO CONSENSUS
        if(!enoughResponses(transaction.getPrepareAns(), 1))
            return new ResponseEntity<>(null, null, HttpStatus.NOT_ACCEPTABLE);

        call.commit(sec.getPasswordReadyToSend(new Password(input)));

        //Wait for enough responses or transaction expires
        while(!enoughResponses(transaction.getCommitsAns(), 1) && !transaction.hasExpired());

        //NO CONSENSUS
        if(!enoughResponses(transaction.getCommitsAns(), 1))
            return new ResponseEntity<>(null, null, HttpStatus.NOT_ACCEPTABLE);

        Optional<Password> pwd = this.passwordRepository.findByUserFingerprintAndDomainAndUsernameAndVersionNumber(
                fingerprint,
                input.domain,
                input.username,
                input.versionNumber);

        if (pwd.isPresent()) {
            return new ResponseEntity<>(sec.getPasswordReadyToSendToClient(pwd.get()), null, HttpStatus.CONFLICT);
        } else {
            Optional<User> user = this.userRepository.findByFingerprint(fingerprint);
            if (user.isPresent()) {
                Password newPwd = passwordRepository.save(new Password(
                        user.get(),
                        input.domain,
                        input.username,
                        input.password,
                        input.versionNumber,
                        input.deviceId,
                        input.pwdSignature,
                        input.timestamp,
                        input.nonce,
                        input.reqSignature
                ));

                System.out.println(serverName + ": New password registered. ID: " + newPwd.getId());

                // #floodAndBeCool
                Password[] retrieved = call.putPassword(sec.getPasswordReadyToSend(new Password(input)));

                //for(Password p : retrieved) System.out.println(p);
                ArrayList<Password> passwordList = new ArrayList<>(Arrays.asList(retrieved));
                passwordList.add(newPwd);

                //System.out.println(passwordList);
                if (!enoughResponses(passwordList.toArray())) {
                    System.out.println(serverName + ": Not enough responses from other replicas");
                    this.passwordRepository.deleteById(newPwd.getId());
                    return new ResponseEntity<>(null, null, HttpStatus.NOT_ACCEPTABLE);
                } else {
                    Object[] sortedQuorum = sortForMostRecentPassword(passwordList.toArray());
                    final Password selectedPassword = (Password) sortedQuorum[0];
                    selectedPassword.setId(newPwd.getId());
                    Password _newPwd = this.passwordRepository.save(selectedPassword);
                    System.out.println("BATATA: " + fingerprint + "##" + _newPwd.domain + "##" + _newPwd.username);
                    ArrayList<Password> passwords = new ArrayList<>(this.passwordRepository.findByUserFingerprintAndDomainAndUsername(
                            fingerprint,
                            input.domain,
                            input.username
                    ));
                    if (!passwords.isEmpty()) {
                        System.out.println(passwords);
                    }
                    // System.out.println(serverName + ": New password really registered. ID: " + _newPwd.getId());
                    return new ResponseEntity<>(sec.getPasswordReadyToSendToClient(_newPwd)
                            , null, HttpStatus.CREATED);
                }
            } else {
                System.out.println(serverName + ": User already registered");
                return new ResponseEntity<>(null, null, HttpStatus.UNAUTHORIZED);
            }
        }
    }


    @RequestMapping(value = "/prePrepare", method = RequestMethod.PUT)
    ResponseEntity<?> prePrepare(@RequestBody Password input) throws NoSuchAlgorithmException, InvalidPasswordSignatureException, ExpiredTimestampException, InvalidKeyException, InvalidRequestSignatureException, DuplicateRequestException, SignatureException, InvalidKeySpecException, UnrecoverableKeyException, KeyStoreException, IOException {
        sec.verifyPasswordInsertSignature(input);
        synchronized (this) {
            Transaction transaction = transactions.get(input);

            if(transaction == null || transaction.getState() != Transaction.INIT_STATE) // pre prepare verify
                return new ResponseEntity<>(null, null, HttpStatus.LOCKED);

            //not first time calling prePrepare, we'll answer ok, bc we're locked
            if(!transaction.setPrePrepareState()){
                return new ResponseEntity<>(null, null, HttpStatus.OK);
            }

            call.prepare(sec.getPasswordReadyToSend(input));
            return new ResponseEntity<Object>(null, null, HttpStatus.OK);
        }
    }

    @RequestMapping(value = "/prepare", method = RequestMethod.PUT)
    ResponseEntity<?> prepare(@RequestBody Password input) throws NoSuchAlgorithmException, InvalidPasswordSignatureException, ExpiredTimestampException, InvalidKeyException, InvalidRequestSignatureException, DuplicateRequestException, SignatureException, InvalidKeySpecException, UnrecoverableKeyException, KeyStoreException, IOException {
        sec.verifyPasswordInsertSignature(input);
        synchronized (this) {
            Transaction transaction = transactions.get(input);

            if(transaction == null || transaction.getState() < Transaction.PREPREPARE_STATE)
                return new ResponseEntity<>(null, null, HttpStatus.LOCKED);

            transaction.addPrepare(input);

            Password toSend = sec.getPasswordReadyToSend(input);

            //já foi chamado
            if(!transaction.setPrepareState())
                return new ResponseEntity<Object>(toSend, null, HttpStatus.OK);

            //Wait for enough responses or transaction expires
            while(!enoughResponses(transaction.getPrepareAns(), 1) && !transaction.hasExpired());

            //NO CONSENSUS
            if(!enoughResponses(transaction.getPrepareAns(), 1))
                return new ResponseEntity<>(null, null, HttpStatus.NOT_ACCEPTABLE);

            call.commit(toSend);
            return new ResponseEntity<Object>(toSend, null, HttpStatus.OK);
        }
    }

    //This is a replica's putPassword
    @RequestMapping(value = "/commit", method = RequestMethod.PUT)
    ResponseEntity<?> commit(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, ExpiredTimestampException, DuplicateRequestException, InvalidPasswordSignatureException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException, IOException {
        String fingerprint = this.validateUser(input.publicKey);
        sec.verifyPasswordInsertSignature(input);

        Transaction transaction = transactions.get(input);

        if(transaction == null || transaction.getState() < Transaction.PREPARE_STATE)
            return new ResponseEntity<>(null, null, HttpStatus.LOCKED);

        transaction.addCommit(input);
        Password toSend = sec.getPasswordReadyToSend(input);

        //já foi chamado
        if(!transaction.setPrepareState())
            return new ResponseEntity<Object>(toSend, null, HttpStatus.OK);

        //Wait for enough responses or transaction expires
        while(!enoughResponses(transaction.getCommitsAns(), 1) && !transaction.hasExpired());

        //NO CONSENSUS
        if(!enoughResponses(transaction.getCommitsAns(), 1))
            return new ResponseEntity<>(null, null, HttpStatus.NOT_ACCEPTABLE);

        Optional<Password> pwd = this.passwordRepository.findByUserFingerprintAndDomainAndUsernameAndVersionNumber(
                fingerprint,
                input.domain,
                input.username,
                input.versionNumber);

        if (pwd.isPresent()) {
            return new ResponseEntity<>(sec.getPasswordReadyToSendToClient(pwd.get()), null, HttpStatus.CONFLICT);
        } else {
            Optional<User> user = this.userRepository.findByFingerprint(fingerprint);
            if (user.isPresent()) {
                Password newPwd = passwordRepository.save(new Password(
                        user.get(),
                        input.domain,
                        input.username,
                        input.password,
                        input.versionNumber,
                        input.deviceId,
                        input.pwdSignature,
                        input.timestamp,
                        input.nonce,
                        input.reqSignature
                ));

                System.out.println(serverName + ": New password registered. ID: " + newPwd.getId());

                // #floodAndBeCool
                Password[] retrieved = call.putPassword(sec.getPasswordReadyToSend(new Password(input)));

                //for(Password p : retrieved) System.out.println(p);
                ArrayList<Password> passwordList = new ArrayList<>(Arrays.asList(retrieved));
                passwordList.add(newPwd);

                //System.out.println(passwordList);
                if (!enoughResponses(passwordList.toArray())) {
                    System.out.println(serverName + ": Not enough responses from other replicas");
                    this.passwordRepository.deleteById(newPwd.getId());
                    return new ResponseEntity<>(null, null, HttpStatus.NOT_ACCEPTABLE);
                } else {
                    Object[] sortedQuorum = sortForMostRecentPassword(passwordList.toArray());
                    final Password selectedPassword = (Password) sortedQuorum[0];
                    selectedPassword.setId(newPwd.getId());
                    Password _newPwd = this.passwordRepository.save(selectedPassword);
                    System.out.println("BATATA: " + fingerprint + "##" + _newPwd.domain + "##" + _newPwd.username);
                    ArrayList<Password> passwords = new ArrayList<>(this.passwordRepository.findByUserFingerprintAndDomainAndUsername(
                            fingerprint,
                            input.domain,
                            input.username
                    ));
                    if (!passwords.isEmpty()) {
                        System.out.println(passwords);
                    }
                    // System.out.println(serverName + ": New password really registered. ID: " + _newPwd.getId());
                    return new ResponseEntity<>(sec.getPasswordReadyToSendToClient(_newPwd)
                            , null, HttpStatus.CREATED);
                }
            } else {
                System.out.println(serverName + ": User already registered");
                return new ResponseEntity<>(null, null, HttpStatus.UNAUTHORIZED);
            }
        }
    }

    private Object[] sortForMostRecentPassword(Object[] toSort) {
        // Sort to get the most recent version
        Arrays.sort(toSort);
        return toSort;
    }

    private boolean enoughResponses(Object[] retrieved) {
        int n = call.size();
        /* If there were more responses than the number of faults we tolerate, then we will proceed.
        *  The expression (2.0 / 3.0) * n - 1.0 / 6.0) is N = 3f + 1 solved in order to F
        */
        return countNotNull(retrieved) > (2.0 / 3.0) * n - 1.0 / 6.0;
    }

    private boolean enoughResponses(Object[] retrieved, int ignored) {
        int n = call.size();
        /* If there were more responses than the number of faults we tolerate, then we will proceed.
        *  The expression (2.0 / 3.0) * n - 1.0 / 6.0) is N = 3f + 1 solved in order to F
        */
        return countNotNull(retrieved) > (2.0 / 3.0) * n - 1.0 / 6.0 - ignored;
    }

    private int countNotNull(Object[] array) {
        int count = 0;
        for (Object o : array) if (o != null) count++;
        return count;
    }

    /**
     * Only verify if user is already registered
     *
     * @param publicKey
     * @return fingerprint
     * @throws NoSuchAlgorithmException
     */
    private String validateUser(String publicKey) throws NoSuchAlgorithmException {
        String fingerprint = sec.generateFingerprint(publicKey);
        this.userRepository.findByFingerprint(fingerprint).orElseThrow(
                () -> new UserNotFoundException());
        return fingerprint;
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Something is wrong.")
    @ExceptionHandler({IOException.class})
    public void ioException() {
        System.err.println("Something is wrong.");
    }

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Request is not correctly signed")
    @ExceptionHandler({InvalidRequestSignatureException.class})
    public void invalidRequestSignatureException() {
        System.err.println("Request is not correctly signed.");
    }

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Password is not correctly signed")
    @ExceptionHandler({InvalidPasswordSignatureException.class})
    public void invalidPasswordSignatureException() {
        System.err.println("Password is not correctly signed.");
    }

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Request expired")
    @ExceptionHandler({ExpiredTimestampException.class})
    public void expiredTimestampException() {
        System.err.println("Request expired.");
    }

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Request already received")
    @ExceptionHandler({DuplicateRequestException.class})
    public void duplicateRequestException() {
        System.err.println("Request already received");
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Something is missing.")
    @ExceptionHandler({NullPointerException.class})
    public void nullException() {
        System.err.println("Something is missing.");
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Cryptographic algorithm is not available.")
    @ExceptionHandler({NoSuchAlgorithmException.class})
    public void noAlgorithm() {
        System.err.println("Cryptographic algorithm is not available.");
    }


    private class ClearExpiredTransactions extends TimerTask {

        public ClearExpiredTransactions() {
            new Timer().schedule(this, ThreadLocalRandom.current().nextInt(5, 11) * 1000);
        }

        @Override
        public void run() {
            for (Password p: transactions.keySet()) {
                Transaction t = transactions.get(p);
                //FIXME ??? TEMPO
                if (t.hasExpired()) {
                    transactions.put(p, null);
                }
            }
            new ClearExpiredTransactions();
        }
    }
}