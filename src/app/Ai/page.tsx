"use client";
import { Button } from "@/components/ui/button"


function NewGame() {

  const handleSubmit = async (event : any) => {
    event.preventDefault();

    try {
      const response = await fetch('/api/chess', {
        method: 'POST'
      });

      const data = await response.json();

      if (data.success) {
        window.location.href = data.redirectUrl;
        console.log("data.redirectUrl",data.redirectUrl);
      } else {
        // Handle error (e.g., display error message)
        console.error('Login failed:', data.error);
      }
    } catch (error) {
      console.error('An error occurred:', error);
    }
  };

  return (
    <form onSubmit={handleSubmit} method="POST">
      <Button type="submit">
        new game
      </Button>
    </form>
  )
}

export default NewGame