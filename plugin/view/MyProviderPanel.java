package raverside.view;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import resources.Icons;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.IOException;
import resources.ResourceManager;

public class MyProviderPanel extends JPanel {
    public JTextField apiTextField;
    public JComboBox<String> functionComboBox;
    public JTextArea textArea;
    public JTextField questionArea;
    public JButton analysePatternsButton;
    public JButton clearButton;
    public JScrollPane scrollPane;
    public JButton sendButton;
    private JCheckBox sendCodeCheckBox;

    public JButton renameVariablesButton;
    public JLabel searchLabel;
    public JTextField searchField;


    public MyProviderPanel() {
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 0;
        gbc.weightx = 1.0;

        var line = -1;

        // Panel construction
        gbc.gridy = ++line;
        gbc.weighty = 0;
        add(createRagButtonPanel(), gbc);

        gbc.gridy = ++line;
        gbc.weighty = 0;
        add(createMiscellaneousPanel(), gbc);

        gbc.gridy = ++line;
        gbc.weighty = 1.0;
        add(createChatIAPanel(), gbc);


    }

    private JPanel createRagButtonPanel() {
        JPanel ragButtonPanel = new JPanel();
        ragButtonPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        apiTextField = new JTextField();
        apiTextField.setForeground(Color.GRAY);
        apiTextField.setText("Enter your Hugging Face API key...");
        apiTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (apiTextField.getText().equals("Enter your Hugging Face API key...")) {
                    apiTextField.setText("");
                    apiTextField.setForeground(Color.BLACK);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (apiTextField.getText().isEmpty()) {
                    apiTextField.setForeground(Color.GRAY);
                    apiTextField.setText("Enter your Hugging Face API key...");
                }
            }
        });

        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        ragButtonPanel.add(apiTextField, gbc);

        return ragButtonPanel;
    }

    private JPanel createMiscellaneousPanel() {
        JPanel miscellaneousPanel = new JPanel();
        miscellaneousPanel.setLayout(new GridBagLayout());
        miscellaneousPanel.setBorder(BorderFactory.createTitledBorder("Miscellaneous"));

        searchLabel = new JLabel("Search:");
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        labelConstraints.gridwidth = 2;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        labelConstraints.insets = new Insets(5, 5, 0, 5);
        miscellaneousPanel.add(searchLabel, labelConstraints);

        searchField = new JTextField();
        GridBagConstraints searchConstraints = new GridBagConstraints();
        searchConstraints.gridx = 0;
        searchConstraints.gridy = 1;
        searchConstraints.gridwidth = 2;
        searchConstraints.fill = GridBagConstraints.HORIZONTAL;
        searchConstraints.weightx = 1.0;
        searchConstraints.insets = new Insets(5, 5, 5, 5);
        miscellaneousPanel.add(searchField, searchConstraints);

        functionComboBox = new JComboBox<>(new String[]{"Select a function"});
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.gridwidth = 2;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.insets = new Insets(5, 5, 5, 5);
        miscellaneousPanel.add(functionComboBox, constraints);

        analysePatternsButton = new JButton("Analyse");
        constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = 3;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 0.5;
        constraints.insets = new Insets(5, 5, 5, 5);
        miscellaneousPanel.add(analysePatternsButton, constraints);

        renameVariablesButton = new JButton("Rename/Retype");
        constraints = new GridBagConstraints();
        constraints.gridx = 1;
        constraints.gridy = 3;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 0.5;
        constraints.insets = new Insets(5, 5, 5, 5);
        miscellaneousPanel.add(renameVariablesButton, constraints);

        return miscellaneousPanel;
    }

    private JPanel createChatIAPanel() {
        JPanel chatIAPanel = new JPanel();
        chatIAPanel.setLayout(new BorderLayout());
        chatIAPanel.setBorder(BorderFactory.createTitledBorder("Chat"));

        textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);

        scrollPane = new JScrollPane(textArea);

        textArea.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { scrollDown(); }
            public void removeUpdate(DocumentEvent e) { scrollDown(); }
            public void changedUpdate(DocumentEvent e) { scrollDown(); }
            private void scrollDown() {
                JScrollBar verticalBar = scrollPane.getVerticalScrollBar();
                verticalBar.setValue(verticalBar.getMaximum());
            }
        });

        sendCodeCheckBox = new JCheckBox("Send code");
        clearButton = new JButton("Clear");
        clearButton.setIcon(Icons.CLEAR_ICON);
        clearButton.setToolTipText("Clear chat history");

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        topPanel.add(sendCodeCheckBox);
        topPanel.add(clearButton);

        questionArea = new JTextField();
        questionArea.setForeground(Color.GRAY);
        questionArea.setText("Write your message...");
        questionArea.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (questionArea.getText().equals("Write your message...")) {
                    questionArea.setText("");
                    questionArea.setForeground(Color.BLACK);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (questionArea.getText().isEmpty()) {
                    questionArea.setForeground(Color.GRAY);
                    questionArea.setText("Write your message...");
                }
            }
        });

        JPanel bottomPanel = new JPanel(new BorderLayout());
        JPanel betweenPanel = new JPanel(new BorderLayout());
        betweenPanel.add(topPanel, BorderLayout.CENTER);

        sendButton = new JButton("SEND");


        betweenPanel.add(sendButton, BorderLayout.WEST);

        bottomPanel.add(questionArea, BorderLayout.CENTER);
        bottomPanel.add(betweenPanel, BorderLayout.EAST);

        chatIAPanel.add(scrollPane, BorderLayout.CENTER);
        chatIAPanel.add(bottomPanel, BorderLayout.SOUTH);


        return chatIAPanel;
    }

    public void resetQuestionArea() {
        textArea.requestFocus();
        questionArea.setText("Write your message...");
        questionArea.setForeground(Color.GRAY);
    }

    public boolean isSendCodeEnabled() {
        return sendCodeCheckBox.isSelected();
    }
}
