import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BiFunction;
import java.util.regex.*;
import java.util.stream.*;
import java.nio.file.*;
import java.security.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.*;
import java.net.NetworkInterface;
class Input {
        public static String str(String prompt) {
            System.out.print(prompt);
            Scanner sc = new Scanner(System.in);
            return sc.nextLine();
        }
        public static int integer(String prompt) {
            try {
                return Integer.parseInt(str(prompt));
            } catch (NumberFormatException e) {
                System.err.println("Invalid argument: " + e.getMessage());
                return 0;
            }
        }
        public static boolean safe(String str) {
            return str.matches("[a-zA-Z0-9/_\\.\\-:]+");
        }
        public static boolean isValidHost(String host) {
            String regex = "^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?([.][a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$";
            return host.matches(regex);
        }
    }
    class cmd {
        public static String capture(List<String> args) {
            String cmd = String.join(" ", args);
            try {
                Process process = new ProcessBuilder(args).start();
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                process.waitFor();
                return output.toString();
            } catch (IOException | InterruptedException e) {
                System.err.println("[ERROR] Command execution failed.");
                return "";
            }
        }
        public static void run(List<String> args) {
            capture(args);  // Just invoke capture for side effects
        }
    }
    //Will make sence in time these two classes here: ^
public class Laurie {
    private static final Logger logger = Logger.getLogger(emmy.class.getName());

    static class SafeCalc {
        // Keep your existing SafeCalc code here (unchanged)
    }

    static class Tool {
        public static String getInput(String prompt) {
            Scanner sc = new Scanner(System.in);
            System.out.print(prompt);
            String input = sc.nextLine();
            return input.trim();
        }

        public static String cmd(String cmd) {
            try {
                Process process = new ProcessBuilder(cmd.split(" ")).start();
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            } catch (IOException e) {
                logger.warning("Error running command: " + e.getMessage());
                return "Error running command: " + cmd;
            }
        }

        // Get local device information
        public static void getDeviceInfo() {
            try {
                System.out.println("Device Information:");

                // Hostname
                String hostname = InetAddress.getLocalHost().getHostName();
                System.out.println("Hostname: " + hostname);

                // IP Address
                InetAddress ip = InetAddress.getLocalHost();
                System.out.println("IP Address: " + ip.getHostAddress());

                // MAC Address
                NetworkInterface network = NetworkInterface.getByInetAddress(ip);
                byte[] mac = network.getHardwareAddress();
                if (mac != null) {
                    StringBuilder macAddress = new StringBuilder();
                    for (int i = 0; i < mac.length; i++) {
                        macAddress.append(String.format("%02X:", mac[i]));
                    }
                    System.out.println("MAC Address: " + macAddress.toString().substring(0, macAddress.length() - 1));
                }

                // Hardware Specs: OS Name, Architecture, and Version
                System.out.println("OS: " + System.getProperty("os.name"));
                System.out.println("OS Architecture: " + System.getProperty("os.arch"));
                System.out.println("Java Version: " + System.getProperty("java.version"));
                System.out.println("Available processors: " + Runtime.getRuntime().availableProcessors());
                System.out.println("Total Memory (in bytes): " + Runtime.getRuntime().totalMemory());
            } catch (Exception e) {
                logger.warning("Error retrieving device information: " + e.getMessage());
                System.out.println("Error retrieving device information.");
            }
        }

        // Create a directory
        public static void mdir() {
            try {
                String dirName = getInput("Directory name: ");
                cmd("mkdir -p " + dirName);
                System.out.println("Directory created: " + dirName);
            } catch (Exception e) {
                logger.severe("Failed to create directory: " + e.getMessage());
                System.out.println("Error creating directory.");
            }
        }

        // Read a file
        public static void read(String filename) {
            try {
                BufferedReader reader = new BufferedReader(new FileReader(filename));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (FileNotFoundException e) {
                logger.warning("File not found: " + filename);
                System.out.println("File not found!");
            } catch (IOException e) {
                logger.warning("Error reading file: " + e.getMessage());
                System.out.println("Error reading file.");
            }
        }

        // Write to a file
        public static void write(String filename) {
            try {
                String data = getInput("> ");
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename, true))) {
                    writer.write(data);
                }
            } catch (IOException e) {
                logger.warning("Error writing to file: " + e.getMessage());
                System.out.println("Error writing to file.");
            }
        }

        // Append to a file
        public static void appendFile() {
            try {
                String filename = getInput("Filename: ");
                String data = getInput("Text to append: ");
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename, true))) {
                    writer.append(data);
                }
                System.out.println("Data appended to " + filename);
            } catch (IOException e) {
                logger.warning("Error appending to file: " + e.getMessage());
                System.out.println("Error appending to file.");
            }
        }

        // Remove a file
        public static void removeFile() {
            String filename = getInput("Enter the filename to delete: ");
            File file = new File(filename);
            if (file.exists() && file.isFile()) {
                if (file.delete()) {
                    System.out.println("File deleted successfully.");
                } else {
                    System.out.println("Failed to delete the file.");
                }
            } else {
                System.out.println("File not found or it's not a valid file.");
            }
        }  // Remove a directory (modified to accept a path)
        public static void removeDirectory(String dirPath) {
            File dir = new File(dirPath);
            if (dir.exists() && dir.isDirectory()) {
                File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        removeDirectory(file.getAbsolutePath()); // Recursively remove subdirectories
                } else {
                    file.delete();
                }
            }
        }
            if (dir.delete()) {
                System.out.println("Directory deleted successfully.");
            } else {
            System.out.println("Failed to delete the directory.");
            }
        } else {
            System.out.println("Directory not found or it's not a valid directory.");
        }
    }
        public static void sfile(String filename, String search) {
            try {
                Process process = new ProcessBuilder("grep", "-i", search, filename).start();
                process.waitFor();
            } catch (IOException | InterruptedException e) {
                logger.warning("Error searching file: " + e.getMessage());
                System.out.println("Search failed.");
            }
        }

        // Generate random password
        public static String mkpasswd() {
            String letters = "abcdefghijklmnopqrstuvwxyz";
            String digits = "0123456789";
            String specials = "!@#$%^&*";
            StringBuilder password = new StringBuilder();
            password.append(letters.charAt(new Random().nextInt(letters.length())));  // Start with a letter
            for (int i = 0; i < 7; i++) {
                int choice = new Random().nextInt(3);
                switch (choice) {
                    case 0:
                        password.append(letters.charAt(new Random().nextInt(letters.length())));
                        break;
                    case 1:
                        password.append(digits.charAt(new Random().nextInt(digits.length())));
                        break;
                    case 2:
                        password.append(specials.charAt(new Random().nextInt(specials.length())));
                        break;
                }
            }
            String generatedPassword = password.toString();
            System.out.println("Password: " + generatedPassword);
            return generatedPassword;
        }

        // Whois, Dig, and Host lookup
        public static void wdh() {
            try {
                String domain = getInput("Domain: ");
                String save = getInput("Save to disk? (y/n): ").toLowerCase();
                if ("y".equals(save)) {
                    String filename = getInput("Filename: ");
                    try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
                        String whoisResult = cmd("whois " + domain);
                        String digResult = cmd("dig " + domain);
                        String hostResult = cmd("host " + domain);
                        
                        writer.write(whoisResult);
                        writer.write(digResult);
                        writer.write(hostResult);
                    } catch (IOException e) {
                        logger.warning("Error saving output: " + e.getMessage());
                        System.out.println("Error saving output.");
                    }
                } else {
                    System.out.println(cmd("whois " + domain));
                    System.out.println(cmd("dig " + domain));
                    System.out.println(cmd("host " + domain));
                }
            } catch (Exception e) {
                logger.warning("Error during whois, dig, host lookup: " + e.getMessage());
                System.out.println("Error during lookup.");
            }
        }

        // Streaming earnings calculator
        public static void strcalc() {
            try {
                double spotifyHigh = 0.005, spotifyLow = 0.003;
                double soundcloudHigh = 0.004, soundcloudLow = 0.0025;
                double amazonMusicHigh = 0.005, amazonMusicLow = 0.004;
                double youtubeHigh = 0.003, youtubeLow = 0.0003;
                double appleMusicHigh = 0.01, appleMusicLow = 0.006;
                int streams = Integer.parseInt(getInput("How many streams? "));
                System.out.println("Spotify: High $" + (spotifyHigh * streams) + ", Low $" + (spotifyLow * streams));
                System.out.println("SoundCloud: High $" + (soundcloudHigh * streams) + ", Low $" + (soundcloudLow * streams));
                System.out.println("Amazon Music: High $" + (amazonMusicHigh * streams) + ", Low $" + (amazonMusicLow * streams));
                System.out.println("YouTube: High $" + (youtubeHigh * streams) + ", Low $" + (youtubeLow * streams));
                System.out.println("Apple Music: High $" + (appleMusicHigh * streams) + ", Low $" + (appleMusicLow * streams));
            } catch (NumberFormatException e) {
                logger.warning("Invalid number of streams entered: " + e.getMessage());
                System.out.println("Invalid input for streams.");
            }
        }
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        String choice = "";
        while (!choice.equals("exit")) {
            System.out.println("\n...Laurie...\n");
            System.out.println("Create Directory (mdir)\n");
            System.out.println("Read File (read)\n");
            System.out.println("Write File (write)\n");
            System.out.println("Append to File (append)\n");
            System.out.println("Search in File (sfile)\n");
            System.out.println("Generate Password (mkpasswd)\n");
            System.out.println("Whois, dig, host (wdh)\n");
            System.out.println("Streaming Earnings Calculator (strcalc)\n");
            System.out.println("Device Info (deviceinfo)\n"); // Added option
            System.out.println("Remove File (removefile)\n"); // Added option
            System.out.println("Remove Directory (removedir)\n"); // Added option
            System.out.println("Help\n");
            System.out.println("Exit\n");
            System.out.print("Enter choice: ");
            choice = sc.nextLine();
            switch (choice) {
                case "mdir":
                    Tool.mdir();
                    break;
                case "read":
                    Tool.read(Tool.getInput("File to read: "));
                    break;
                case "write":
                    Tool.write(Tool.getInput("File to write: "));
                    break;
                case "append":
                    Tool.appendFile();
                    break;
                case "sfile":
                    Tool.sfile(Tool.getInput("File name: "), Tool.getInput("Search string: "));
                    break;
                case "mkpasswd":
                    Tool.mkpasswd();
                    break;
                case "wdh":
                    Tool.wdh();
                    break;
                case "strcalc":
                    Tool.strcalc();
                    break;
                case "deviceinfo":
                    Tool.getDeviceInfo();  // Added new option for device info
                    break;
                case "removefile":
                    Tool.removeFile();  // Added new option for file removal
                    break;
                case "removedir":
                    String dirname = Input.str("Directory name: ");
                    Tool.removeDirectory(dirname);  // Added new option for directory removal
                    break;
                case "help":
                    printHelp();
                    break;
                case "exit":
                    System.out.println("Ctr+C exit's");
                    break;
                default:
                    System.out.println("Unknown command, please select a valid option.");
            }
        }
    }
    private static void printHelp() {
        System.out.println("\nHelp Menu\n");
        System.out.println("Welcome to Laurie!");
        System.out.println("You can perform the following tasks:");
        System.out.println("- Create directories, read/write files, append text.");
        System.out.println("- Search within files.");
        System.out.println("- Generate random secure passwords.");
        System.out.println("- Perform network lookups (whois, dig, host).");
        System.out.println("- Calculate streaming service earnings based on number of streams.");
        System.out.println("- Get information about your local device.");
        System.out.println("- Remove files and directories.");
        System.out.println("\nTip: You can view the source code of this tool to see how it works!");
        System.out.println("Simply open the Java file and explore the classes and methods.\n");
    }
}
