const express = require("express");
const Jobs = require("../schemas/Jobs");
const router = express.Router();
const { body, validationResult } = require("express-validator");




// Get all jobs matching given profession route: GET /api/jobs
router.get('/getjobs/:en', async (req, res) => {
    try {
        const en = req.params.en.toString();

        const jobs = await Jobs.find({ 'hiring.en': en }).populate('posterId');
        res.status(200).json({ success: true, data: jobs });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// Get all jobs posted by a particular user route: GET /api/jobs/poster/:posterId
router.get('/poster/:posterId', async (req, res) => {

    try {
        const { posterId } = req.params;
        const jobs = await Jobs.find({ posterId }).populate('bids.userId');
        res.json({ success: true, data: jobs });
    } catch (err) {
        console.error(err.message);
        res.status(500).send({ success: false, error: 'Server error' });
    }
});

// Get a particular job route: GET /api/jobs/getjob/:id
router.get('/getjob/:id', async (req, res) => {
    try {
        const job = await Jobs.findById(req.params.id).populate('bids.userId');
        if (!job) {
            return res.status(404).json({ success: false, error: 'Job not found' });
        }
        return res.json({ success: true, job });
    } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
    }
});


// Post a job route: POST /api/jobs/postjob
router.post('/postjob', [
    body('title').notEmpty().withMessage('Title is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('budget').notEmpty().withMessage('Budget is required'),
    body('posterId').notEmpty().withMessage('PosterId is required'),
    body('hiring').notEmpty().withMessage('Hiring is required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { title, description, budget, posterId, hiring, bids } = req.body;
    try {
        const job = new Jobs({ title, description, budget, posterId, hiring, bids });
        await job.save();
        res.json({ success: true, job });
    } catch (err) {
        console.error(err.message);
        res.status(500).send({ success: false, error: 'Server error' });
    }
});


// 
router.post('/applyforjob', [
    body('message').notEmpty().withMessage('message is required'),
    body('jobId').notEmpty().withMessage('JobId is required'),
    body('userId').notEmpty().withMessage('UserId is required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { message, jobId, userId } = req.body;

    try {
        const job = await Jobs.findById(jobId);
        if (!job) {
            return res.status(404).json({ success: false, error: 'Job not found' });
        }

        job.bids.push({ userId, message });
        await job.save();

        res.json({ success: true, data: job });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});




module.exports = router;
