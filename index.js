const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ActivityType, PermissionsBitField } = require('discord.js');
const express = require('express');
const axios = require('axios');

// ================= CONFIGURATION =================
const CONFIG = {
    TOKEN: process.env.TOKEN,
    CHANNEL_ID: '1477009832136675459',
    GUILD_ID: process.env.GUILD_ID, // ID de ton serveur Discord (à mettre en variable d'env)
    VERIFIED_ROLE_ID: '1477009575210258616',

    CLIENT_ID: '1477022309964320964',
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    REDIRECT_URI: process.env.REDIRECT_URI, // https://xwwcx.onrender.com/callback

    SITE_URL: 'testuhq.netlify.app',

    WEBHOOK_URL: 'https://discord.com/api/webhooks/1477023473439342814/OBT0i0X5VBqXsfWTatYzsFa2q3jqDF7T4K3vb31oJ-uTJUSC19kM3bu2aCpPTCmaaJB2',

    // ProxyCheck API (gratuit jusqu'à 1000 req/jour - inscription sur proxycheck.io)
    PROXYCHECK_API_KEY: process.env.PROXYCHECK_API_KEY || '',

    STATUS: '/verify | vexio'
};
// =================================================

// Stockage en mémoire des utilisateurs déjà vérifiés (évite les doublons de compte)
const verifiedIPs = new Set();
const verifiedDiscordIDs = new Set();

// ---------- PARTIE 1 : BOT DISCORD ----------
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers
    ]
});

client.once('ready', async () => {
    console.log(`✅ Bot connecté : ${client.user.tag}`);

    client.user.setPresence({
        activities: [{ name: CONFIG.STATUS, type: ActivityType.Playing }],
        status: 'online'
    });

    try {
        const channel = await client.channels.fetch(CONFIG.CHANNEL_ID);

        const embed = new EmbedBuilder()
            .setColor(0x5865F2)
            .setTitle('🔐 Vérification Vexio')
            .setDescription(
                '> Bienvenue sur **Vexio** !\n\n' +
                'Pour accéder à l\'ensemble du serveur, vous devez vous vérifier via Discord.\n\n' +
                '**Pourquoi ?**\n' +
                '• Protéger la communauté contre les bots & raids\n' +
                '• Empêcher les comptes multiples\n' +
                '• Garantir une expérience sûre\n\n' +
                '**Comment ?**\n' +
                '➜ Cliquez sur **Vérifier** ci-dessous et autorisez l\'application.\n\n' +
                '*La vérification est instantanée et sécurisée.*'
            )
            .setImage('https://cdn.discordapp.com/attachments/1460483668228313243/1475611536167927969/XEYES-FIdfsdNAL.png?ex=69a2bb15&is=69a16995&hm=f47de5c62513d217527b1c5ac50a80545ee1352dbad50d9982c2c42dce8e77b1&')
            .setFooter({ text: 'Vexio Security • Anti-VPN & Anti-Alts actif' })
            .setTimestamp();

        const oauth2Link =
            `https://discord.com/api/oauth2/authorize?` +
            `client_id=${CONFIG.CLIENT_ID}` +
            `&redirect_uri=${encodeURIComponent(CONFIG.REDIRECT_URI)}` +
            `&response_type=code` +
            `&scope=identify%20email%20guilds.join`;

        const button = new ButtonBuilder()
            .setLabel('✅ Vérifier')
            .setURL(oauth2Link)
            .setStyle(ButtonStyle.Link);

        const row = new ActionRowBuilder().addComponents(button);

        await channel.send({ embeds: [embed], components: [row] });
        console.log('✅ Message de vérification Vexio envoyé.');
    } catch (error) {
        console.error('❌ Erreur bot:', error.message);
    }
});

client.login(CONFIG.TOKEN);

// ---------- PARTIE 2 : BACKEND EXPRESS ----------
const app = express();

app.use((req, res, next) => {
    console.log(`📨 ${req.method} ${req.url}`);
    next();
});

// Récupérer l'IP réelle
async function getPublicIP(req) {
    let ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    if (ip?.includes('::ffff:')) ip = ip.split('::ffff:')[1];
    if (ip === '127.0.0.1' || ip === '::1') {
        try {
            const r = await axios.get('https://api.ipify.org?format=json', { timeout: 3000 });
            return r.data.ip;
        } catch { return ip; }
    }
    return ip;
}

// Vérification Anti-VPN via ProxyCheck.io
async function checkVPN(ip) {
    try {
        const apiKey = CONFIG.PROXYCHECK_API_KEY;
        const url = apiKey
            ? `https://proxycheck.io/v2/${ip}?key=${apiKey}&vpn=1&asn=1`
            : `https://proxycheck.io/v2/${ip}?vpn=1`;
        const response = await axios.get(url, { timeout: 5000 });
        const data = response.data;
        if (data && data[ip]) {
            const result = data[ip];
            const isProxy = result.proxy === 'yes';
            const isVPN = result.type === 'VPN' || result.type === 'Tor';
            return { isVPN: isProxy || isVPN, type: result.type || 'Unknown', provider: result.provider || 'Unknown' };
        }
        return { isVPN: false };
    } catch (err) {
        console.error('⚠️ ProxyCheck erreur:', err.message);
        return { isVPN: false }; // En cas d'erreur API, on laisse passer
    }
}

// Assigner le rôle via le bot
async function assignRole(userId) {
    try {
        const guild = await client.guilds.fetch(CONFIG.GUILD_ID);
        const member = await guild.members.fetch(userId);
        await member.roles.add(CONFIG.VERIFIED_ROLE_ID);
        console.log(`✅ Rôle assigné à ${member.user.username}`);
        return true;
    } catch (err) {
        console.error('❌ Erreur assignation rôle:', err.message);
        return false;
    }
}

// Route principale OAuth2 callback
app.get('/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) return res.redirect(`${CONFIG.SITE_URL}?error=no_code`);

    try {
        // 1. Échange du code contre un token
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token',
            new URLSearchParams({
                client_id: CONFIG.CLIENT_ID,
                client_secret: CONFIG.CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: CONFIG.REDIRECT_URI
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );

        const accessToken = tokenResponse.data.access_token;

        // 2. Infos utilisateur
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });
        const user = userResponse.data;
        console.log(`👤 ${user.username} (${user.id})`);

        // 3. Vérification double compte (même ID Discord)
        if (verifiedDiscordIDs.has(user.id)) {
            console.log(`⚠️ Double compte détecté: ${user.username}`);
            return res.redirect(`${CONFIG.SITE_URL}?error=alt_account`);
        }

        // 4. Récupération IP
        const ip = await getPublicIP(req);
        console.log(`🌐 IP: ${ip}`);

        // 5. Vérification double compte (même IP)
        if (verifiedIPs.has(ip)) {
            console.log(`⚠️ IP déjà vérifiée: ${ip}`);
            return res.redirect(`${CONFIG.SITE_URL}?error=alt_account`);
        }

        // 6. Anti-VPN
        const vpnCheck = await checkVPN(ip);
        if (vpnCheck.isVPN) {
            console.log(`🚫 VPN détecté: ${ip} (${vpnCheck.type})`);

            // Log dans le webhook
            await axios.post(CONFIG.WEBHOOK_URL, {
                embeds: [{
                    title: '🚫 VPN Bloqué - Vexio',
                    color: 0xFF0000,
                    fields: [
                        { name: '👤 Utilisateur', value: `${user.username}#${user.discriminator}`, inline: true },
                        { name: '🆔 ID', value: user.id, inline: true },
                        { name: '🌐 IP', value: ip, inline: true },
                        { name: '🔒 Type', value: vpnCheck.type, inline: true },
                        { name: '🏢 Provider', value: vpnCheck.provider, inline: true }
                    ],
                    footer: { text: 'Vexio Security' },
                    timestamp: new Date()
                }]
            });

            return res.redirect(`${CONFIG.SITE_URL}?error=vpn_detected`);
        }

        // 7. Tout est OK → Enregistrer + assigner le rôle
        verifiedIPs.add(ip);
        verifiedDiscordIDs.add(user.id);

        const roleAssigned = await assignRole(user.id);

        // 8. Log webhook succès
        await axios.post(CONFIG.WEBHOOK_URL, {
            embeds: [{
                title: '✅ Nouvelle Vérification - Vexio',
                color: 0x5865F2,
                fields: [
                    { name: '👤 Utilisateur', value: `${user.username}#${user.discriminator}`, inline: true },
                    { name: '🆔 ID', value: user.id, inline: true },
                    { name: '📧 Email', value: user.email || 'Non fourni', inline: true },
                    { name: '🌐 IP', value: ip, inline: true },
                    { name: '🎭 Rôle', value: roleAssigned ? '✅ Assigné' : '❌ Échec', inline: true },
                    { name: '🕒 Heure', value: new Date().toLocaleString('fr-FR'), inline: true }
                ],
                thumbnail: { url: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` },
                footer: { text: 'Vexio Security • Anti-VPN actif' },
                timestamp: new Date()
            }]
        });

        // 9. Redirection succès
        res.redirect(`${CONFIG.SITE_URL}?success=true&user=${encodeURIComponent(user.username)}`);

    } catch (error) {
        console.error('❌ Erreur callback:', error.response?.data || error.message);
        res.redirect(`${CONFIG.SITE_URL}?error=auth_failed`);
    }
});

app.get('/', (req, res) => {
    res.send('✅ Vexio Security Backend - Online');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`🌐 Backend démarré sur le port ${port}`);
    console.log(`🔗 Callback URI: ${CONFIG.REDIRECT_URI}`);
});

process.on('unhandledRejection', (error) => {
    console.error('❌ Erreur non gérée:', error);
});
