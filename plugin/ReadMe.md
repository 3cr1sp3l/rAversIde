# Raverside Plugin for Ghidra

## Introduction

Welcome to the Raverside Plugin for Ghidra. This plugin enhances your Ghidra experience by providing advanced functionalities such as code analysis, renaming suggestions, and an interactive chatbot. This guide will walk you through the installation process and how to use each feature effectively.

## Table of Contents

1. [Installation](#installation)
2. [Setup](#setup)
3. [Features](#features)
    - [Analysis](#analysis)
    - [Rename](#rename)
    - [Chatbot](#chatbot)
4. [Getting an API Key](#getting-an-api-key)
5. [Troubleshooting](#troubleshooting)

## Installation

To install the Raverside Plugin, follow these steps:

1. **Download the Plugin**: Download the ZIP file containing the Raverside Plugin from the provided link.
2. **Open Ghidra**: Launch Ghidra on your computer.
3. **Install the Extension**:
    - Navigate to `File` > `Install Extensions`.
    - Click the `+` button and select the downloaded ZIP file.
4. **Restart Ghidra**: After installation, restart Ghidra to apply the changes.

## Setup

Upon restarting Ghidra, follow these steps to configure the plugin:

1. **Activate the Plugin**:
    - Go to `Window` > `RaversidePlugin` if the window does not appear automatically.
    - If it still does not appear, navigate to `File` > `Configure` and ensure `RaversidePlugin` is activated.
2. **Enter API Key**:
    - Obtain your API key from [Hugging Face](https://huggingface.co/settings/tokens) under the settings and access tokens section.
    - Enter this key at the top of the Raverside plugin interface.

## Features

### Analysis

The analysis feature allows you to run a thorough inspection of the functions within your program.

- **Full Program Analysis**: Analyze all functions within the program.
- **Selective Analysis**: Choose specific functions to analyze.
- **Results**: A summary of detected issues will appear in a window, with vulnerable lines highlighted based on their severity:
    - **LOW** (Yellow)
    - **MEDIUM** (Orange)
    - **HIGH** (Red)

### Rename

This feature provides intelligent suggestions for renaming functions:

- **Select a Function**: You must select a function to receive renaming suggestions.
- **AI Suggestions**: The AI will propose meaningful names, which you can accept or modify as needed.

### Chatbot

The chatbot allows for interactive communication with the AI model:

- **Send Code**: Optionally send code snippets to the chatbot.
- **Conversation History**: The conversation history is saved for reference.
- **Clear History**: Use the `Clear` button to delete the conversation history.

## Getting an API Key

To use the Raverside Plugin's features, you need an API key from Hugging Face:

1. Go to [Hugging Face Settings](https://huggingface.co/settings/tokens).
2. Generate a new API token if you don't already have one.
3. Copy the token and paste it into the API key field in the Raverside plugin.

## Troubleshooting

- **Plugin Window Not Appearing**: Ensure the plugin is activated in `File` > `Configure`.
- **API Key Issues**: Verify that the API key is correctly entered and valid.
- **Analysis Results Not Showing**: Check if the functions are correctly selected and that the plugin is activated.

---

Thank you for using the Raverside Plugin for Ghidra. We hope this guide helps you get the most out of our plugin. Happy coding!
