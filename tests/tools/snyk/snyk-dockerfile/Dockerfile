FROM node:20-alpine

RUN npm install -g snyk
RUN snyk test --severity-threshold=high

CMD ["node", "index.js"]
