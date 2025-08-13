# Setup Guide – Splunk SOC Simulation

This guide will walk you through setting up Splunk Enterprise, importing your SOC sample logs, creating field extractions, and preparing for alert creation.

---

## 0. Download & Install Splunk Enterprise
1. Visit [https://www.splunk.com](https://www.splunk.com)
<img width="1918" height="975" alt="Splunk" src="https://github.com/user-attachments/assets/e3ce8a72-eee2-47a5-aab0-6fc04bc7e820" />


2. Navigate to **Products → Splunk Enterprise**
3. Click **Free Trial** and choose your OS (Windows, Linux, or macOS)
4. Create a free Splunk account (if not already registered)
5. Download the installer
<img width="1882" height="877" alt="Splunk_Download" src="https://github.com/user-attachments/assets/0ba294ed-19d3-4788-9281-be364c0cb196" />

   
6. Install using the default options (you may change the install directory if needed)
7. During installation, set an **admin username and password** (remember these!)

---

## 1. Access Splunk Web Interface
- Open your browser and go to:  
http://localhost:8000
<img width="1916" height="969" alt="image" src="https://github.com/user-attachments/assets/6a6c59e4-b8ea-426b-8f8a-b9e5052dc3e9" />

- Log in with the **admin credentials** you created during installation.
- You should now see the Splunk **Home Dashboard**.

---

## 2. Import Sample Data
1. From the Splunk Home page, click **Settings → Add Data**
<img width="1886" height="880" alt="image" src="https://github.com/user-attachments/assets/a755834f-2aeb-4735-99bc-49398cac9b8f" />


2. Choose **Upload**
<img width="1261" height="881" alt="Splunk_Upload_Log_File" src="https://github.com/user-attachments/assets/b8d93cfb-fbe4-4b1f-a642-47608a66937a" />


3. Browse and select `SOC_Task2_Sample_Logs.csv`
<img width="1911" height="862" alt="Splunk_Upload_Log_File3" src="https://github.com/user-attachments/assets/2240d541-ff29-4253-ab79-ced839b5fdf1" />


4. Click **Next** and  Set **Source type** as `csv`
<img width="1911" height="862" alt="Splunk_Upload_Log_File3" src="https://github.com/user-attachments/assets/6a126466-a1b1-4f04-9681-3acafb6a27aa" />


5. Click **Review → Submit** to finish import
<img width="1911" height="415" alt="Splunk_Upload_Log_File5" src="https://github.com/user-attachments/assets/0be6c30a-dd02-4bd5-9e22-bb21a12504ea" />

## 3. Create Field Extractions
Once the data is imported, run the following SPL in **Search & Reporting** to extract key fields:
* - It is used to return all the data
<img width="1908" height="892" alt="Splunk_Search_Command" src="https://github.com/user-attachments/assets/a7c012d4-41bc-4a17-90d1-7bb4b87dcac9" />


To add a particular id or variable to filter search, right click on it and click add to search and enter to find the filtered results
<img width="1912" height="812" alt="Splunk_Search_Command2" src="https://github.com/user-attachments/assets/49ddd806-7092-40d8-8013-61e36761d78f" />


By default it will show the results of uploaded file or system logs:
<img width="1907" height="887" alt="Splunk_Search" src="https://github.com/user-attachments/assets/cb488dad-b767-48fd-adcd-ee96048da668" />
