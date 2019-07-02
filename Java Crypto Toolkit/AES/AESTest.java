package EncryptionToolkit.AES;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * AESTest
 *
 * @author: Marco
 * Date: 2019/6/28 11:00
 */
public class AESTest {
    private static int SIM_ROUND = 1000;
    private static boolean DEBUG_MODE = false;
    private static volatile int completedRound = 0;
    private static ThreadPoolExecutor pool;
    private static boolean multiThreadCompleted = false;

    static {
        pool = (ThreadPoolExecutor) Executors.newFixedThreadPool(
                Runtime.getRuntime().availableProcessors());
    }

    private AESTest() {}

    public static AESTest getInstance() {
        return new AESTest();
    }

    public void doTest() {
        doMultiThreadTest();
        doSingleThreadTest();
    }

    public void doMultiThreadTest() {
        AES aes = AES.initWithKeySize(128);
        aes.setKeyGenerationIteration(94872);

        completedRound = 0;
        final long startTime = System.currentTimeMillis();

        for (int i = 0; i < SIM_ROUND; i++) {
            int currentRound = i + 1;
            pool.execute(() -> {
                aes.doEncryptDecrypt(DEBUG_MODE);

                if (DEBUG_MODE) {
                    System.out.println("======================================================");
                }

                if (currentRound % 100 == 0) {
                    System.out.println("COMPLETED: " + currentRound * 100 / SIM_ROUND + " %...");
                }

                synchronized  (AESTest.class) {
                    completedRound += 1;

                    if (completedRound == SIM_ROUND) {
                        long timeLapse = System.currentTimeMillis() - startTime;
                        System.out.println("TOTAL TIME WITH THREAD POOL: " + timeLapse + " ms");
                        System.out.println("AVERAGE TIME WITH THREAD POOL: " + timeLapse / SIM_ROUND + " ms");
                        multiThreadCompleted = true;

                        synchronized (this) {
                            notifyAll();
                        }
                    }
                }
            });
        }
    }

    public void doSingleThreadTest() {
        // Single thread execution
        synchronized (this) {
            while (!multiThreadCompleted) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        long startTime = System.currentTimeMillis();

        AES aes = AES.initWithKeySize(128);
        aes.setKeyGenerationIteration(94872);

        for (int i = 0; i < SIM_ROUND; i++) {
            aes.doEncryptDecrypt(DEBUG_MODE);

            if (DEBUG_MODE) {
                System.out.println("======================================================");
            }

            if (i % 100 == 0) {
                System.out.println("COMPLETED: " + i * 100 / SIM_ROUND + " %...");
            }
        }

        long totalTime = System.currentTimeMillis() - startTime;
        System.out.println("TOTAL TIME WITH THREAD POOL: " + totalTime + " ms");
        System.out.println("AVERAGE TIME WITHOUT THREAD POOL: " + totalTime / SIM_ROUND + " ms");
    }
}
