import { Post } from '../models/post.model.js';

const createPostService = (name, description, age) => {
  return Post.create({
    name,
    description,
    age,
  });
};

const getPostsService = () => {
  return Post.find();
};

const getPostService = (id) => {
  return Post.findById(id);
};

const updatePostService = (id, updateData) => {
  return Post.findByIdAndUpdate(id, updateData, {
    new: true,
    runValidators: true,
  });
};

const deletePostService = (id) => {
  return Post.findByIdAndDelete(id);
};

export {
  createPostService,
  getPostsService,
  getPostService,
  updatePostService,
  deletePostService,
};
