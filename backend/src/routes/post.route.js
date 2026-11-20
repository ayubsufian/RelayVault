import { Router } from 'express';
import {
  createPost,
  deletePost,
  getPosts,
  getPost,
  updatePost,
} from '../controllers/post.controller.js';

const router = Router();

router.route('/').post(createPost).get(getPosts);
router.route('/:id').get(getPost).patch(updatePost).delete(deletePost);

export default router;
