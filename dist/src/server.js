"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const app_js_1 = __importDefault(require("./app.js"));
const prisma_js_1 = require("./lib/prisma.js");
const PORT = Number(process.env.PORT) || 5000;
async function startServer() {
    try {
        await prisma_js_1.prisma.$connect();
        app_js_1.default.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    }
    catch (error) {
        console.error("Failed to start the server:", error);
        await prisma_js_1.prisma.$disconnect();
        process.exit(1);
    }
}
startServer();
