function generatePinCode() {
    const min = 1000; // Minimum PIN value (inclusive)
    const max = 9999; // Maximum PIN value (inclusive)

    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateDateAfterTwoMinutes() {
    const currentTime = Date.now();
    const twoMinutesInMillis = 2 * 60 * 1000; // 2 minutes in milliseconds
    const futureTime = currentTime + twoMinutesInMillis;

    return new Date(futureTime);
}

module.exports = {
    generatePinCode,
    generateDateAfterTwoMinutes
}
