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
public class laurie1 {
    private static final Logger logger = Logger.getLogger(laurie1.class.getName());
    static class SafeCalc {
        private static final Map<Class<?>, BiFunction<Double, Double, Double>> OPS = new HashMap<>();
        static {
            OPS.put(ast.Add.class, (a, b) -> a + b);
            OPS.put(ast.Sub.class, (a, b) -> a - b);
            OPS.put(ast.Mult.class, (a, b) -> a * b);
            OPS.put(ast.Div.class, (a, b) -> a / b);
            OPS.put(ast.Mod.class, (a, b) -> a % b);
            OPS.put(ast.Pow.class, (a, b) -> Math.pow(a, b));
            OPS.put(ast.FloorDiv.class, (a, b) -> Math.floor(a / b));  // Floor division
            OPS.put(ast.USub.class, (a, b) -> -a);
            OPS.put(ast.UAdd.class, (a, b) -> a);
        }
        public static double evalExpr(String expr) {
            try {
                return executeCommand(expr);
            } catch (Exception e) {
                logger.severe("Evaluation error: " + e.getMessage());
                throw e;  // Re-throw to propagate the error
            }
        }
        private static double executeCommand(String expr) throws IllegalArgumentException {
            return eval(ast.parse(expr));
        }
        private static double eval(Object node) throws UnsupportedOperationException {
            if (node instanceof ast.BinOp) {
                ast.BinOp binOp = (ast.BinOp) node;
                double left = eval(binOp.getLeft());
                double right = eval(binOp.getRight());
                return OPS.get(binOp.getOperator().getClass()).apply(left, right);
            } else if (node instanceof ast.UnaryOp) {
                ast.UnaryOp unaryOp = (ast.UnaryOp) node;
                double operand = eval(unaryOp.getOperand());
                return OPS.get(unaryOp.getOperator().getClass()).apply(operand, 0.0);
            } else if (node instanceof ast.Num) {
                return ((ast.Num) node).getValue();
            } else if (node instanceof ast.Constant) {
                return ((ast.Constant) node).getValue();
            } else {
                throw new UnsupportedOperationException("Unsupported expression: " + node);
            }
        }
    }
    class ast {
    static class Add {}
    static class Sub {}
    static class Mult {}
    static class Div {}
    static class Mod {}
    static class Pow {}
    static class FloorDiv {}
    static class USub {}
    static class UAdd {}
    static class BinOp {
        private Object left;
        private Object right;
        private Object operator;
        public BinOp(Object left, Object right, Object operator) {
            this.left = left;
            this.right = right;
            this.operator = operator;
        }
        public Object getLeft() {
            return left;
        }
        public Object getRight() {
            return right;
        }

        public Object getOperator() {
            return operator;
        }
    }
    static class UnaryOp {
        private Object operand;
        private Object operator;

        public UnaryOp(Object operand, Object operator) {
            this.operand = operand;
            this.operator = operator;
        }

        public Object getOperand() {
            return operand;
        }

        public Object getOperator() {
            return operator;
        }
    }

    static class Num {
        private double value;

        public Num(double value) {
            this.value = value;
        }

        public double getValue() {
            return value;
        }
    }
    static class Constant {
        private double value;

        public Constant(double value) {
            this.value = value;
        }

        public double getValue() {
            return value;
        }
    }
    public static Object parse(String expr) {
        // Here you should implement the logic to parse a mathematical expression
        // For simplicity, let's just return a constant for now
        return new Num(10);  // Placeholder
    }
}
    static class Tool {
        public static String getInput(String prompt) {
            Scanner sc = new Scanner(System.in);
            System.out.print(prompt);
            String input = sc.nextLine();
            // Sanitize input to prevent injection
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
        public static void sfile(String filename, String search) {
            try {
                Process process = new ProcessBuilder("grep", "-i", search, filename).start();
                process.waitFor();
            } catch (IOException | InterruptedException e) {
                logger.warning("Error searching file: " + e.getMessage());
                System.out.println("Search failed.");
            }
        }
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
        System.out.println("\n=== Help Menu ===");
        System.out.println("Welcome to the Utility Tool!");
        System.out.println("You can perform the following tasks:");
        System.out.println("- Create directories, read/write files, append text.");
        System.out.println("- Search within files.");
        System.out.println("- Generate random secure passwords.");
        System.out.println("- Perform network lookups (whois, dig, host).");
        System.out.println("- Calculate streaming service earnings based on number of streams.");
        System.out.println("\nTip: You can view the source code of this tool to see how it works!");
        System.out.println("Simply open the Java file and explore the classes and methods.\n");
    }
}
