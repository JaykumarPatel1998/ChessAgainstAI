"use client"
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

function SignInPage() {
  const handleSubmit = async (event : any) => {
    event.preventDefault();
    console.log("event",event);
    
    const form = event.target;
    const formData = new FormData(form);
    console.log("formData",formData);

    try {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        body: formData,
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
    <Card className="relative flex flex-col w-full p-8 sm:max-w-md justify-center gap-2">
      <form className="flex-1 flex flex-col w-full justify-center gap-2 text-foreground" onSubmit={handleSubmit} method="post">

        <input
          className="hidden"
          type="text"
          name="username"
          placeholder="username"
          value={"guest@rtg3"}
          readOnly
        />
        <input
          className="hidden"
          type="password"
          name="password"
          placeholder="••••••••"
          value={"123456"}
          readOnly
        />
        <Button
          type='submit'
          variant={"default"}
        >
          Quick Play as Guest
        </Button>

      </form>



      <span className='text-center '>or enter your credentials</span>
      <hr />

      <form className="flex-1 flex flex-col w-full justify-center gap-2 text-foreground" onSubmit={handleSubmit} method="post">
        <label className="text-md" htmlFor="username">
          Username
        </label>
        <input
          className="rounded-md px-4 py-2 bg-inherit border mb-6"
          name="username"
          placeholder="username"
          required
        />

        <label className="text-md" htmlFor="password">
          Password
        </label>
        <input
          className="rounded-md px-4 py-2 bg-inherit border mb-6"
          type="password"
          name="password"
          placeholder="••••••••"
          required
        />
        <Button
          type='submit'
          variant={"default"}
        >
          Sign In
        </Button>

      </form>
      <small>Don&apos;t have an account? <a href="/signup" className='underline decoration-blue-500'>Sign up here</a></small>
    </Card>
  )
}

export default SignInPage;