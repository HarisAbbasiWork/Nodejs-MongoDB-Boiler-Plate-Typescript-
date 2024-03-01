import nodemailer from 'nodemailer';
//import twilio from 'twilio';
//console.log("process.env.TWILIO_ACCOUNT_SID ",process.env.TWILIO_ACCOUNT_SID," process.env.TWILIO_AUTH_TOKEN ",process.env.TWILIO_AUTH_TOKEN)
//const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

export const sendEmail = async (email: string, subject: string, html: string): Promise<boolean> => {
  let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.PASSWORD,
    },
  });
  let mailOptions = {
    from: 'no-reply@creditbutterfly.ai',
    to: email,
    subject: subject,
    html: html,
    fromName: 'Creditbutterfly'
  }
  const response=await transporter.sendMail(mailOptions).then((data:any) => {
    console.log("data ", data)
    return true
  }).catch((err:any) => {
    console.log("err ", err)
    return false
  })
  return response
}

// export const sendMessage = async (to: string, message: string): Promise<boolean> => {
//   try {
//     const response=await client.messages
//       .create({
//         body: message,
//         to: `+${to}`,
//         from: "+1(608) 680-3421",
//       })
//       .then(async (message:any) => {
//         console.log(message);
//         return true
//       })
//       .catch((error:any) => {
//         console.log(error);
//         return false
//       });
//       return response
//   } catch (error) {
//     console.error("Error sending message:", error);
//     return false;
//   }
// };
