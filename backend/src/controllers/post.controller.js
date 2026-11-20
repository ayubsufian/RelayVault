import mongoose from 'mongoose';
import {
  createPostService,
  getPostsService,
  getPostService,
  updatePostService,
  deletePostService,
} from '../services/post.service.js';
import HttpError from '../utils/http-error.js';

const createPost = async (req, res) => {
  const { name, description, age } = req.body;

  if (!name || !description || !age) {
    throw new HttpError('All fields are required', 400);
  }

  const post = await createPostService(name, description, age);

  return res.status(201).json({ message: 'Post created successfully', post });
};

const getPosts = async (req, res) => {
  const posts = await getPostsService();
  return res.status(200).json({ posts });
};

const getPost = async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    throw new HttpError('Invalid post ID', 400);
  }

  const post = await getPostService(req.params.id);

  if (!post) {
    throw new HttpError('Post not found', 404);
  }

  return res.status(200).json({ post });
};

const updatePost = async (req, res) => {
  if (Object.keys(req.body).length === 0) {
    throw new HttpError('No data provided for an update', 400);
  }

  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    throw new HttpError('Invalid post ID', 400);
  }

  const post = await updatePostService(req.params.id, req.body);

  if (!post) {
    throw new HttpError('Post not found', 404);
  }

  return res.status(200).json({ message: 'Post updated successfully', post });
};

const deletePost = async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    throw new HttpError('Invalid post ID', 400);
  }

  const post = await deletePostService(req.params.id);

  if (!post) {
    throw new HttpError('Post not found', 404);
  }

  return res.status(204).send();
};

export { createPost, getPosts, getPost, updatePost, deletePost };
