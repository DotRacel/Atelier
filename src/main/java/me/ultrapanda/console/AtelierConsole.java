package me.ultrapanda.console;

import me.ultrapanda.Atelier;
import me.ultrapanda.logger.AtelierLogger;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.IOException;

public class AtelierConsole {
    private final String prompt;

    private static final AtelierLogger logger = Atelier.atelierLogger;

    public AtelierConsole(String prompt) {
        this.prompt = prompt;
    }

    public void start(){
        Terminal terminal = null;
        try {
            terminal = TerminalBuilder.builder().dumb(true).build();
        } catch (IOException exception) {
            logger.error("初始化控制台失败.");
            exception.printStackTrace();

            System.exit(-1);
        }

        ConsoleThread consoleThread = new ConsoleThread(prompt, terminal, LineReaderBuilder.builder().terminal(terminal).build());
        consoleThread.start();
    }
}
