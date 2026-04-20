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
import java.nio.file.attribute.*;
import java.util.logging.*;
import java.util.stream.*;
public class Laurie3 {
    private static final Logger logger = Logger.getLogger(Laurie3.class.getName());
    private static final String OS = System.getProperty("os.name").toLowerCase();
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
    static class ast {
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
            // Placeholder for expression parsing, which would return a number
            return new Num(10);  // Temporary placeholder for simplicity
        }
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
                ProcessBuilder processBuilder;
                if (OS.contains("win")) {
                    processBuilder = new ProcessBuilder("cmd", "/c", cmd); // Windows
                } else {
                    processBuilder = new ProcessBuilder(cmd.split(" ")); // Unix-like systems
                }
                Process process = processBuilder.start();
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
                // Cross-platform directory creation
                File dir = new File(dirName);
                if (!dir.exists()) {
                    boolean created = dir.mkdirs();
                    if (created) {
                        System.out.println("Directory created: " + dirName);
                    } else {
                        System.out.println("Failed to create directory.");
                    }
                } else {
                    System.out.println("Directory already exists: " + dirName);
                }
            } catch (Exception e) {
                logger.severe("Failed to create directory: " + e.getMessage());
                System.out.println("Error creating directory.");
            }
        }
        public static void read(String filename) {
            try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
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
                // Cross-platform search command: 'grep' for Linux/macOS, 'findstr' for Windows
                String searchCommand = OS.contains("win") ? "findstr /i " + search : "grep -i " + search;
                Process process = new ProcessBuilder(searchCommand.split(" ")).start();
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

         public static void mapDirectory(String dirPath) {
            try {
                Path startPath = Paths.get(dirPath);
                if (!Files.exists(startPath) || !Files.isDirectory(startPath)) {
                    System.out.println("The specified path does not exist or is not a directory.");
                    return;
                }
                // Walk through the directory tree and print out the structure
                Files.walkFileTree(startPath, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                        String indent = getIndentation(dir, startPath);
                        System.out.println(indent + "[DIR] " + dir.getFileName());
                        return FileVisitResult.CONTINUE;
                    }
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        String indent = getIndentation(file.getParent(), startPath);
                        System.out.println(indent + "[FILE] " + file.getFileName());
                        return FileVisitResult.CONTINUE;
                    }
                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                        logger.warning("Error visiting file: " + exc.getMessage());
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException e) {
                logger.warning("Error mapping directory: " + e.getMessage());
                System.out.println("Error mapping directory.");
            }
        }
        private static String getIndentation(Path path, Path startPath) {
            int depth = path.getNameCount() - startPath.getNameCount();
            StringBuilder indent = new StringBuilder();
            for (int i = 0; i < depth; i++) {
                indent.append("  ");
            }
            return indent.toString();
            }
        }
        public static void evalExpression() {
            try {
                String expr = Tool.getInput("Enter a mathematical expression (e.g., 3 + 5): ");
                double result = SafeCalc.evalExpr(expr);
                System.out.println("Result: " + result);
                } catch (Exception e) {
                    System.out.println("Error evaluating expression: " + e.getMessage());
                }
            }
        public static void parseAndEvaluateExpression() {
            try {
                String expr = Tool.getInput("Enter a simple mathematical expression to parse (e.g., 3 + 5): ");
                Object parsedExpr = ast.parse(expr);
                double result = SafeCalc.evalExpr(parsedExpr.toString()); // Uses SafeCalc to evaluate
                System.out.println("Parsed and Evaluated Result: " + result);
            } catch (Exception e) {
                System.out.println("Error parsing or evaluating expression: " + e.getMessage());
            }
        }
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        String choice = "";
        printHelp();
        while (!choice.equals("exit")) {
            choice = sc.nextLine();
            switch (choice) {
                case "eval":
                    evalExpression();
                    break;
                case "parseeval":
                    parseAndEvaluateExpression();
                    break;
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
                case "mapdir":
                    Tool.mapDirectory(Tool.getInput("Enter directory path to map: "));
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
        System.out.println("\n...Laurie...\n");
        System.out.println("Evaluate Expression (eval)\n");
        System.out.println("Parse and Evaluate Expression (parseeval)\n");
        System.out.println("Create Directory (mdir)\n");
        System.out.println("Read File (read)\n");
        System.out.println("Write File (write)\n");
        System.out.println("Append to File (append)\n");
        System.out.println("Search in File (sfile)\n");
        System.out.println("Generate Password (mkpasswd)\n");
        System.out.println("Whois, dig, host (wdh)\n");
        System.out.println("Streaming Earnings Calculator (strcalc)\n");
        System.out.println("Map Directory Structure (mapdir)\n");  // New option
        System.out.println("Help\n");
        System.out.println("Exit\n");
        System.out.print("Enter choice:");
    }
}
