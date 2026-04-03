


### 3. Space Hardware
* Leave it as **CPU Basic (Free)**. Our environment is highly optimized and doesn't need a GPU!

### 4. Visibility
* Leave it as **Public** so the Hackathon judges can view it.

### 5. Create Space!
* Click the **Create Space** button at the very bottom.

---

## 🔗 What to do immediately after clicking "Create Space":

Once the space is created, it will look completely empty. Hugging Face will show you some confusing Git commands. **Ignore them!** There is a much faster way:

1. Look in the top right corner of your new Space and click the **Settings** tab.
2. Scroll down until you find the section called **"Pull requests and Repository linking"** (or something related to GitHub integration).
3. Paste the URL to your GitHub Repository:
   `https://github.com/Sansyuh06/CVE-Triage-Env`
4. Click **Connect/Sync**.

That's it! Hugging Face will automatically download your code, read our `Dockerfile`, build the React UI, and launch the API server on port 7860. It will take about 2-3 minutes to build. Once it says "Running", your app is live!
