FROM node:20-alpine

WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

RUN npm install

COPY prisma ./prisma
COPY prisma.config.ts ./

COPY . .

EXPOSE 5001

CMD ["npm", "run", "dev"]