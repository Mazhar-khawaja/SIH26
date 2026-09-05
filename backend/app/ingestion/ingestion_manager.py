cd SIH26
cd ULPF
git init
git remote add origin https://github.com/Mazhar-khawaja/SIH26.git
git add .
git commit -m "Initial project upload"
git pull origin main --allow-unrelated-histories
git branch -M main
git push -u origin main