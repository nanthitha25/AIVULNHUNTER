function Loader({ message = 'Loading...' }) {
  return (
    <div className="loader">
      <div className="spinner"></div>
      <p>{message}</p>
    </div>
  );
}

export default Loader;

