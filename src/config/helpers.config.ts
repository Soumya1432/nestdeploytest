const messages = {
  success: {
    find: ' fetched successfully',
    get: ' fetched successfully',
    create: ' created successfully',
    update: ' updated successfully',
    delete: ' deleted successfully',
  },
  error: {
    find: 'fetch was unsuccessful',
    get: 'fetch was unsuccessful',
    create: ' creation was unsuccessful',
    update: ' updation was unsuccessful',
    delete: ' deletion was unsuccessful',
  },
};

const slugify = (str: string): string => {
  str = str.replace(/^\s+|\s+$/g, ''); // trim leading/trailing spaces
  str = str.toLowerCase(); // convert to lowercase
  str = str
    .replace(/[^a-z0-9 -]/g, '') // remove invalid chars
    .replace(/\s+/g, '-') // collapse whitespace and replace by "-"
    .replace(/-+/g, '-'); // collapse dashes
  return str;
};

export { messages, slugify };
