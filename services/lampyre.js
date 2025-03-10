// lampyre.js - Lampyre API Integration for OSINTFox

const axios = require('axios');
const API_TOKEN = process.env.LAMPYRE_API_KEY;
const BASE_URL = 'https://api.lighthouse.lampyre.io/api/1.0';

const createTask = async (jobName, queryData) => {
    const response = await axios.post(`${BASE_URL}/tasks/${jobName}`, {
        token: API_TOKEN,
        task_info: queryData
    });

    return response.data;
};

const getTaskResult = async (jobName, taskId) => {
    const response = await axios.get(`${BASE_URL}/tasks/${jobName}/${taskId}`, {
        params: { token: API_TOKEN }
    });

    return response.data;
};

const lampyreSearch = async (type, query) => {
    let task;
    switch (type) {
        case 'ip':
            task = await createTask('test_ip_geoip_v1', { ip: query });
            break;
        case 'username':
            task = await createTask('username_checker_v1', { username: query });
            break;
        case 'phone':
            task = await createTask('phone_leakcheck_v1', { phone: query });
            break;
        case 'email':
            task = await createTask('email_spotify_checker_v1', { email: query });
            break;
        case 'photo_exif':
            task = await createTask('image_exif_v1', { image_url: query });
            break;
        case 'photo_face':
            task = await createTask('image_search4faces_v1', { image_url: query });
            break;
        case 'photo_reverse':
            task = await createTask('image_google_v1', { image_url: query });
            break;
        default:
            throw new Error('Unsupported search type');
    }

    return task;
};

module.exports = {
    createTask,
    getTaskResult,
    lampyreSearch,
};
