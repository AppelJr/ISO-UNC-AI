unzip ai-system-validator.zip
cd ai-system-validator
git init
git remote add origin https://github.com/Appel420/qrc-aisf-proposal-.git
git checkout -b main
git add .
git commit -m "Initial safe AI system validator scaffold"
# If the remote already has content, consider pulling first:
# git pull --rebase origin main
git push -u origin main