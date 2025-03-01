const express = require('express');
const Campsite = require('../models/campsite');
const authenticate = require('../authenticate');

const campsiteRouter = express.Router();

campsiteRouter.route('/')
    .get((req, res, next) => {
        Campsite.find()
        .populate('comments.author')
        .then(campsites => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(campsites);
        })
        .catch(err => next(err));
    })
    .post(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
        Campsite.create(req.body)
        .then(campsite => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(campsite);
        })
        .catch(err => next(err));
    })
    .put(authenticate.verifyUser, (req, res) => {
        res.statusCode = 403;
        res.end('PUT operation not supported on /campsites');
    })
    .delete(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
        Campsite.deleteMany()
        .then(response => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(response);
        })
        .catch(err => next(err));
    });

campsiteRouter.route('/:campsiteId')
    .get((req, res, next) => {
        Campsite.findById(req.params.campsiteId)
        .populate('comments.author')
        .then(campsite => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(campsite);
        })
        .catch(err => next(err));
    })
    .post(authenticate.verifyUser, (req, res) => {
        res.statusCode = 403;
        res.end(`POST operation not supported on /campsites/${req.params.campsiteId}`);
    })
    .put(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
        Campsite.findByIdAndUpdate(req.params.campsiteId, {
            $set: req.body
        }, { new: true })
        .then(campsite => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(campsite);
        })
        .catch(err => next(err));
    })
    .delete(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
        Campsite.findByIdAndDelete(req.params.campsiteId)
        .then(response => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json(response);
        })
        .catch(err => next(err));
    });

campsiteRouter.route('/:campsiteId/comments')
    .delete(authenticate.verifyUser, authenticate.verifyAdmin, (req, res, next) => {
        Campsite.findById(req.params.campsiteId)
        .then(campsite => {
            if (campsite) {
                campsite.comments = [];
                campsite.save()
                .then(updatedCampsite => {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.json(updatedCampsite);
                })
                .catch(err => next(err));
            } else {
                const err = new Error(`Campsite ${req.params.campsiteId} not found`);
                err.status = 404;
                return next(err);
            }
        })
        .catch(err => next(err));
    });

// Allow users to update or delete **only their own** comments
campsiteRouter.route('/:campsiteId/comments/:commentId')
    .put(authenticate.verifyUser, (req, res, next) => {
        Campsite.findById(req.params.campsiteId)
            .then(campsite => {
                if (!campsite) {
                    const err = new Error(`Campsite ${req.params.campsiteId} not found`);
                    err.status = 404;
                    return next(err);
                }
                
                const comment = campsite.comments.id(req.params.commentId);
                if (!comment) {
                    const err = new Error(`Comment ${req.params.commentId} not found`);
                    err.status = 404;
                    return next(err);
                }

                // Check if the logged-in user is the comment's author
                if (!comment.author.equals(req.user._id)) {
                    res.statusCode = 403;
                    return res.json({ error: 'Forbidden: You can only edit your own comments' });
                }

                // Update comment
                if (req.body.text) {
                    comment.text = req.body.text;
                }

                return campsite.save();
            })
            .then(updatedCampsite => {
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.json(updatedCampsite);
            })
            .catch(err => next(err));
    })

    .delete(authenticate.verifyUser, (req, res, next) => {
        Campsite.findById(req.params.campsiteId)
            .then(campsite => {
                if (!campsite) {
                    const err = new Error(`Campsite ${req.params.campsiteId} not found`);
                    err.status = 404;
                    return next(err);
                }

                const comment = campsite.comments.id(req.params.commentId);
                if (!comment) {
                    const err = new Error(`Comment ${req.params.commentId} not found`);
                    err.status = 404;
                    return next(err);
                }

                // Check if the logged-in user is the comment's author
                if (!comment.author.equals(req.user._id)) {
                    res.statusCode = 403;
                    return res.json({ error: 'Forbidden: You can only delete your own comments' });
                }

                // Delete comment
                comment.remove();
                return campsite.save();
            })
            .then(updatedCampsite => {
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.json(updatedCampsite);
            })
            .catch(err => next(err));
    });

module.exports = campsiteRouter;
