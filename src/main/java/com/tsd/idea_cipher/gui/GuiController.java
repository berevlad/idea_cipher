package com.tsd.idea_cipher.gui;

import java.io.File;

import com.tsd.idea_cipher.modes.FileCipher;
import com.tsd.idea_cipher.modes.OperationMode;
import javafx.application.Platform;
import javafx.concurrent.Worker;
import javafx.scene.control.*;
import javafx.stage.Stage;

import javafx.fxml.FXML;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.FileChooser;

/**
 * Controller for the GUI.
 */
public class GuiController {

    @FXML
    private Button selInput;
    @FXML
    private Button selOutput;
    @FXML
    private ToggleGroup operation;
    @FXML
    private ToggleGroup operationMenu;
    @FXML
    private ToggleGroup operationMode;
    @FXML
    private ToggleGroup operationModeMenu;
    @FXML
    private TextField inputFile;
    @FXML
    private TextField outputFile;
    @FXML
    private RadioButton encrypt;
    @FXML
    private RadioMenuItem encryptMenu;
    @FXML
    private RadioButton decrypt;
    @FXML
    private RadioMenuItem decryptMenu;
    @FXML
    private RadioButton ecb;
    @FXML
    private RadioMenuItem ecbMenu;
    @FXML
    private RadioButton cbc;
    @FXML
    private RadioMenuItem cbcMenu;
    @FXML
    private RadioButton cfb;
    @FXML
    private RadioMenuItem cfbMenu;
    @FXML
    private RadioButton ofb;
    @FXML
    private RadioMenuItem ofbMenu;
    @FXML
    private PasswordField key;
    @FXML
    private Button run;
    @FXML
    private MenuItem runMenu;
    @FXML
    private TextArea status;
    @FXML
    private ProgressBar progressBar;

    private File input;
    private File output;
    private FileCipher task;

    @FXML
    private void initialize() {
        // Controale pentru butoane radio
        operation.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            handleSelectRadio(operation, operationMenu);
        });
        operationMenu.selectedToggleProperty().addListener(observable -> {
            handleSelectRadio(operationMenu, operation);
        });
        operationMode.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            handleSelectRadio(operationMode, operationModeMenu);
        });
        operationModeMenu.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            handleSelectRadio(operationModeMenu, operationMode);
        });
        // Set userDir as default
        inputFile.setText(System.getProperty("user.home").replace("\\", "/"));
        outputFile.setText(System.getProperty("user.home").replace("\\", "/"));
        // Write help
        status.appendText("Select files, choose parameters and press run...");
    }

    /**
     * Selectare fisier de intrare
     */
    @FXML
    private void handleSelectInput() {
        File f = input != null ? selectFile(true, "Select input", input.getParent()) :
                selectFile(true, "Select input");
        if (f != null) {
            input = f;
            inputFile.setText(input.toString().replace("\\", "/"));
        }
    }

    /**
     * Selectare fisier de iesire
     */
    @FXML
    private void handleSelectOutput() {
        File f = input != null ? selectFile(false, "Select output", input.getParent()) :
                selectFile(false, "Select output");
        if (f != null) {
            output = f;
            outputFile.setText(output.toString().replace("\\", "/"));
        }
    }

    /**
     * Rulare cifru.
     */
    @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
    @FXML
    private void handleRun() {
        // Daca e apasat butonul Cancel (cat timp task-ul ruleaza)
        if(handleCancelTask()){
            blockUI(false);
            return;
        }
        // Verificari initiale
        if (input == null || !input.isFile() || output == null) {
            showError("no-file");
            return;
        } else if (key.getText().equals("")) {
            showError("no-key");
            return;
        }
        // Start proces
        blockUI(true);
        boolean encrypt = (((RadioButton) operation.getSelectedToggle()).getText()).equals("Encrypt");
        OperationMode.Mode mode = null;
        switch (((RadioButton) operationMode.getSelectedToggle()).getText()) {
            case "ECB":
                mode = OperationMode.Mode.ECB;
                break;
            case "CBC":
                mode = OperationMode.Mode.CBC;
                break;
            case "CFB":
                mode = OperationMode.Mode.CFB;
                break;
            case "OFB":
                mode = OperationMode.Mode.OFB;
                break;
        }
        resetStatus();
        // Creare task
        task = new FileCipher(input.getPath(), output.getPath(), key.getText(), encrypt, mode);
        task.getStatus().addListener((observable, oldValue, newValue) -> {
            Platform.runLater(() -> println(newValue)); // Afisare mesaj in box-ul de stare
        });
        task.setOnSucceeded(event -> blockUI(false));
        task.setOnFailed(event -> {
            println("Error: " + task.getException().getMessage());
            blockUI(false);
        });
        progressBar.progressProperty().bind(task.progressProperty());
        // Rulare task
        new Thread(task).start();
    }

    /**
     * Inchide aplicatia
     */
    @FXML
    private void handleClose() {
        handleCancelTask();
        System.exit(0);
    }

    /**
     * Afisare info autor.
     */
    @FXML
    private void handleAbout() {
        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Algoritm IDEA");
        alert.setHeaderText("About");
        alert.setContentText("Autori: Bere Vlad, Ghemis George, Baciu Alexandru.");
        alert.showAndWait();
    }

    /**
     * Afisare mesaj in box-ul de stare
     */
    private void println(String msg) {
        status.appendText("\n" + msg);
    }
df
    /**
     * Curatare box de stare
     */
    private void resetStatus() {
        status.clear();
        status.appendText("Let's go!");
    }

    /**
     * Dezactivati sau activati comenzile interfetei
     *
     * @param running true: disable / false: enable
     */
    private void blockUI(boolean running) {
        // Change text of Run button
        if(running) {
            run.setText("Cancel");
            runMenu.setText("Cancel");
        } else {
            run.setText("Run");
            runMenu.setText("Run");
        }
        // Dezactivare / activare butoane radio
        selInput.setDisable(running);
        selOutput.setDisable(running);
        // Dezactivare / actuvare butoane radio
        ToggleGroup[] groups = {operation, operationMenu, operationMode, operationModeMenu};
        for(ToggleGroup g : groups){
            for (Toggle t : g.getToggles()) {
                if(t instanceof RadioButton){
                    ((RadioButton) t).setDisable(running);
                } else {
                    ((RadioMenuItem) t).setDisable(running);
                }
            }
        }
        // Dezactivare / activare cheie de intrare
        key.setDisable(running);
    }

    /**
     * Anulare task.
     *
     * @return true if the cancel was successful
     */
    private boolean handleCancelTask() {
        boolean canceled = false;
        if(task != null && task.getState() == Worker.State.RUNNING) {
            println("The operation was cancelled!");
            canceled = task.cancel();
        }
        return canceled;
    }

    /**
     * Sincronizare RadioButton si RadioMenuItem.
     *
     * @param group group with the newest state
     * @param groupToUpdate group to update
     */
    private void handleSelectRadio(ToggleGroup group, ToggleGroup groupToUpdate) {
        String selected = null;
        for (Toggle t : group.getToggles()) {
            if (t.isSelected()) {
                selected = t instanceof RadioButton ? ((RadioButton) t).getText() : ((RadioMenuItem) t).getText();
                break;
            }
        }
        for (Toggle t : groupToUpdate.getToggles()) {
            String text = t instanceof RadioButton ? ((RadioButton) t).getText() : ((RadioMenuItem) t).getText();
            if (text.equals(selected)) {
                groupToUpdate.selectToggle(t);
            }
        }
    }

    /**
     * Deschide FileChooser pentru selectarea unui fisier.
     *
     * @param open true: open file / false: save file
     * @param title title of the FileChooser
     * @param path path to open
     * @return selected file
     */
    private File selectFile(boolean open, String title, String path) {
        Stage primaryStage = (Stage) inputFile.getScene().getWindow();
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("All files (*.*)", "*.*"));
        fileChooser.setInitialDirectory(new File(path));
        fileChooser.setTitle(title);
        return open ? fileChooser.showOpenDialog(primaryStage) : fileChooser.showSaveDialog(primaryStage);
    }

    /**
     * Deschide FileChooser pentru a selecta un fisier pe calea implicita
     */
    private File selectFile(boolean open, String title) {
        return selectFile(open, title, System.getProperty("user.home"));
    }

    /**
     * Deschide alert box pentru afisare erori.
     */
    private void showError(String error) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Error");
        if (error.equals("no-file")) {
            alert.setHeaderText("No file chosen");
            alert.setContentText("You have to choose the file to encrypt.");
        } else if (error.equals("no-key")) {
            alert.setHeaderText("No key");
            alert.setContentText("You have to enter a key.");
        }
        alert.showAndWait();
    }
}